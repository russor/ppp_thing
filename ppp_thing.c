// A PPPoE client for FreeBSD, using netgraph, which allows session resumption
// and handoff to a peer for high availability PPPoE

// PPP configuration is minimum viable, tested against former Qwest CenturyLink

// Unexpected options will result in the program aborting, and there are
// likely protocol correctness issues. For example:
//    Configure-acks are not checked to confirm they match configure-request
//    Configure-requests are all sent with ID 1
//    Magic numbers aren't required, which is going against a SHOULD

// this could (should?) use kqueue instead of select; but with a handful of fds,
// select isn't too bad

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/random.h>
#include <sys/sockio.h>
#include <time.h>
#include <md5.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdarg.h>


#include <netgraph.h>
#include <netgraph/ng_ether.h>
#include <netgraph/ng_etf.h>
#include <netgraph/ng_pppoe.h>
#include <netgraph/ng_ppp.h>

// listed in /etc/services as any private dial out service. I think this counts
#define PEER_PORT 75

char ETHER_INTERFACE[IF_NAMESIZE], USER[80], PASS[80];
u_char ETHER_ADDR[ETHER_ADDR_LEN];
uint16_t MTU;
struct in_addr CARP_ADDR, CARP_ME, CARP_PEER;

int I_AM_CARP_MASTER;
void discovery_process_state(int, int, u_char *, size_t, size_t);
void ppp_process_state(int, u_char *, size_t, size_t);
void ppp_tick();
void new_state(int);
void load_config();
void load_state();
void send_session_to_peer();

uint8_t ppp_state;

uint16_t ppp_session;
#define TRIES 10
uint8_t ppp_tries;
time_t ppp_time;

struct in_addr ppp_my_ip, ppp_peer_ip;
u_char ppp_ether[ETHER_ADDR_LEN];
uint16_t probable_session;
u_char probable_ether[ETHER_ADDR_LEN];

#define PPP_CLOSED 0
#define PPP_DISCOVERY 1
#define PPP_STARTING 2
#define PPP_LCP_SENT 3
#define PPP_LCP_ACK_SENT 4
#define PPP_LCP_ACK_RCVD 5
#define PPP_CHAP 6
#define PPP_CHAP_SUCCESS 7
#define PPP_IPCP_SENT 8
#define PPP_IPCP_ACK_SENT 9
#define PPP_IPCP_ACK_RCVD 10
#define PPP_UP 11
#define PPP_ZOMBIE 12
#define PPP_CARP_MASTER 256 // pseudo-state

#define SESSION_HOOK "sess_0"

void send_or_die(char * what, int cs, const char *path, int cookie, int cmd, const void *arg,
         size_t arglen) {
    if (NgSendMsg(cs, path, cookie, cmd, arg, arglen) < 0) {
            syslog(LOG_ERR, "failed to send message %s: %d", what, errno);
            exit(1);
    }
}

#define MAX_BUF (64 * 1024)

int ioctls, routes, control, data, peers;

int max(int a, int b) {
    if (a > b) { return a; }
    return b;
}

int main () {
    char path [NG_PATHSIZ];
    u_char buf[MAX_BUF];
    
    openlog("ppp_thing", LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_DAEMON);
    
    if (NgMkSockNode("ppp_thing", &control, &data) < 0) {
        syslog(LOG_ERR, "failed to make node");
        exit(1);
    }

    load_config();
    load_state();
    I_AM_CARP_MASTER = 0;

    if ((routes = socket(PF_ROUTE, SOCK_RAW, AF_INET)) < 0) {
        syslog(LOG_ERR, "route socket: %m");;
        exit(1);
    }
    
    struct rt_msghdr *rt_msg = (struct rt_msghdr*) buf;
    bzero(rt_msg, sizeof(*rt_msg));
    rt_msg->rtm_type = RTM_GET;
    rt_msg->rtm_version = RTM_VERSION;
    rt_msg->rtm_addrs = (RTA_DST | RTA_NETMASK);
    int i = sizeof(*rt_msg);
    struct sockaddr_in *sockaddr = (struct sockaddr_in *)&buf[i];
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = CARP_ADDR.s_addr;
    i += sizeof(*sockaddr);
    sockaddr = (struct sockaddr_in*) &buf[i];
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = INADDR_BROADCAST;
    i += sizeof(*sockaddr);
    rt_msg->rtm_msglen = i;

    if (write(routes, buf, i) == i) {
        syslog(LOG_INFO, "I am CARP master");
        I_AM_CARP_MASTER = 1;
    }


    NgSendMsg(control, "etfA:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);

    struct ngm_mkpeer mkp = {0};
    snprintf(mkp.type, sizeof(mkp.type), "etf");
    snprintf(mkp.ourhook, sizeof(mkp.ourhook), NG_ETHER_HOOK_ORPHAN);
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), NG_ETF_HOOK_DOWNSTREAM);
    snprintf(path, sizeof(path), "%s:", ETHER_INTERFACE);
    uint32_t promisc = 1;
    send_or_die("make ethernet promisc", control, path, NGM_ETHER_COOKIE, NGM_ETHER_SET_PROMISC, &promisc, sizeof(promisc));
    
    struct ifreq ifr;

    bzero(&ifr, sizeof(ifr));
    (void) strlcpy(ifr.ifr_name, ETHER_INTERFACE, sizeof(ifr.ifr_name));
    
    if ((ioctls = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "socket(family AF_INET,SOCK_DGRAM: %m");;
    }

    if (ioctl(ioctls, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        syslog(LOG_ERR, "ioctl (SIOCGIFFLAGS): %m");;
        exit(1);
    }
    uint32_t flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
    flags |= IFF_PPROMISC;
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;
    if (ioctl(ioctls, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        syslog(LOG_ERR, "ioctl (SIOCSIFFLAGS): %m");
        exit(1);
    }
    
    if ((peers = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "peer socket: %m");;
    }
    struct sockaddr_in listen = {0};
    listen.sin_family = AF_INET;
    listen.sin_len = sizeof(listen);
    listen.sin_port = htons(PEER_PORT);
    if (bind(peers, (struct sockaddr *)&listen, sizeof(listen)) != 0) {
        syslog(LOG_ERR, "bind peer socket: %m");;
    }
    
 
    send_or_die("mk_peer etfA", control, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp));

    snprintf(path, sizeof(path), "%s:%s", ETHER_INTERFACE, NG_ETHER_HOOK_ORPHAN);
    NgNameNode(control, path, "etfA");

    NgSendMsg(control, "etfB:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);

    snprintf(mkp.type, sizeof(mkp.type), "etf");
    snprintf(mkp.ourhook, sizeof(mkp.ourhook), "pppoe_sess");
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "pppoe_sess");

    send_or_die("mk_peer etfB", control, "etfA:", NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp));

    NgNameNode(control, "etfA:pppoe_sess", "etfB");
    
    struct ngm_connect connect = {0};
    snprintf(connect.path, sizeof(connect.path), "etfA:");
    snprintf(connect.ourhook, sizeof(connect.ourhook), "ether");
    snprintf(connect.peerhook, sizeof(connect.peerhook), "pppoe_disc");
    
    send_or_die("connect etfA pppoe", control, ".", NGM_GENERIC_COOKIE, NGM_CONNECT, &connect, sizeof(connect));
    snprintf(connect.ourhook, sizeof(connect.ourhook), "pppoe");
    snprintf(connect.path, sizeof(connect.path), "etfB:");
    send_or_die("connect etfB pppoe", control, ".", NGM_GENERIC_COOKIE, NGM_CONNECT, &connect, sizeof(connect));

    struct ng_etffilter etffilter = {0};
    snprintf(etffilter.matchhook, sizeof(etffilter.matchhook), "pppoe_disc");
    etffilter.ethertype = 0x8863;
    send_or_die("filter pppoe disc A", control, "etfA:", NGM_ETF_COOKIE, NGM_ETF_SET_FILTER, &etffilter, sizeof(etffilter));
    send_or_die("filter pppoe disc B", control, "etfB:", NGM_ETF_COOKIE, NGM_ETF_SET_FILTER, &etffilter, sizeof(etffilter));
    snprintf(etffilter.matchhook, sizeof(etffilter.matchhook), "pppoe_sess");
    etffilter.ethertype = 0x8864;
    send_or_die("filter pppoe sess A", control, "etfA:", NGM_ETF_COOKIE, NGM_ETF_SET_FILTER, &etffilter, sizeof(etffilter));
    send_or_die("filter pppoe sess B", control, "etfB:", NGM_ETF_COOKIE, NGM_ETF_SET_FILTER, &etffilter, sizeof(etffilter));
    
    NgSendMsg(control, "pppoe:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
    snprintf(mkp.type, sizeof(mkp.type), "pppoe");
    snprintf(mkp.ourhook, sizeof(mkp.ourhook), NG_ETF_HOOK_DOWNSTREAM);
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), NG_PPPOE_HOOK_ETHERNET);
    send_or_die("mk_peer pppoe", control, "etfB:", NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp));
    NgNameNode(control, "etfB:downstream", "pppoe");
    
    send_or_die("setenaddr", control, "pppoe:", NGM_PPPOE_COOKIE, NGM_PPPOE_SETENADDR, &ETHER_ADDR, sizeof(ETHER_ADDR));

    NgSendMsg(control, "ppp0:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
    snprintf(mkp.type, sizeof(mkp.type), "ppp");
    snprintf(mkp.ourhook, sizeof(mkp.ourhook), "ppp0");
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "bypass");
    send_or_die("mk_peer ppp", control, ".", NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp));
    NgNameNode(control, ".:ppp0", "ppp0");

    struct ng_ppp_node_conf ppp_conf = {0};
    ppp_conf.bund.mrru = MTU;
    ppp_conf.bund.enableIP = 1;
    ppp_conf.links[0].mru = MTU;
    ppp_conf.links[0].bandwidth = 1;
    ppp_conf.links[0].enableLink = 1;
    
    send_or_die("configure ppp0", control, "ppp0:", NGM_PPP_COOKIE, NGM_PPP_SET_CONFIG, &ppp_conf, sizeof(ppp_conf));

    // ng0 is the real interface
    NgSendMsg(control, "ng0:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
    snprintf(mkp.type, sizeof(mkp.type), "iface");
    snprintf(mkp.ourhook, sizeof(mkp.ourhook), "inet");
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet");
    send_or_die("mk_peer iface", control, "ppp0:", NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp));

    // ng1 exists only to hold the real public ip
    NgSendMsg(control, "ng1:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
    snprintf(mkp.type, sizeof(mkp.type), "iface");
    snprintf(mkp.ourhook, sizeof(mkp.ourhook), "inet");
    snprintf(mkp.peerhook, sizeof(mkp.peerhook), "inet");
    send_or_die("mk_peer iface", control, ".", NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp, sizeof(mkp));

    daemon(0, 0);
    new_state(PPP_CLOSED);

    fd_set set;
    
    ssize_t len = 0;
    char hookname[NG_HOOKSIZ];
    struct ng_mesg* msg = malloc(MAX_BUF);
    // todo adjust select timeout depending on state!
    struct timeval one_sec = {1, 0};

    int nfds = max(max(control, data), max(routes, peers)) + 1;
    FD_ZERO(&set);
    while (1) {
        FD_SET(control, &set);
        FD_SET(data, &set);
        FD_SET(routes, &set);
        FD_SET(peers, &set);
        select(nfds, &set, NULL, NULL, &one_sec);
        if (FD_ISSET(control, &set)) {
            if ((len = NgRecvMsg(control, msg, MAX_BUF, path)) > 0) {
                if (I_AM_CARP_MASTER && msg->header.typecookie == NGM_PPPOE_COOKIE && msg->header.cmd == NGM_PPPOE_ACNAME) {
                    syslog(LOG_INFO, "ACNAME from %s: %s", path, msg->data);
                } else if (I_AM_CARP_MASTER && msg->header.typecookie == NGM_PPPOE_COOKIE && msg->header.cmd == NGM_PPPOE_SUCCESS) {
                    if (probable_session) {
                        syslog(LOG_NOTICE, "PPPoE discovery complete, starting session");
                        new_state(PPP_STARTING);
                        probable_session = 0; // clear for future
                    } else {
                        syslog(LOG_NOTICE, "Attempting to resume saved session");
                        new_state(PPP_ZOMBIE);
                    }
                    ppp_tick();
                } else if (msg->header.typecookie == NGM_PPPOE_COOKIE && (msg->header.cmd == NGM_PPPOE_FAIL || msg->header.cmd == NGM_PPPOE_CLOSE)) {
                    syslog(LOG_NOTICE, "FAIL/CLOSE from %s: %s", path, msg->data);
                    if (strncmp(msg->data, SESSION_HOOK, strlen(SESSION_HOOK) + 1) == 0) {
                        ppp_session = 0;
                        new_state(PPP_CLOSED);
                    } 
                } else if (I_AM_CARP_MASTER && msg->header.typecookie == NGM_PPPOE_COOKIE && msg->header.cmd == NGM_PPPOE_SESSIONID) {
                    ppp_session = *(uint16_t*)msg->data;
                    if (ppp_session == probable_session) {
                        bcopy(probable_ether, ppp_ether, ETHER_ADDR_LEN);
                    }
                } else {
                    syslog(LOG_WARNING, "unknown message from %s: cmd = %d, cookie = %d", path, msg->header.cmd, msg->header.typecookie);
                }
            } else {
                syslog(LOG_ERR, "bad recv msg");
                exit(1);
            }
        }
        if (FD_ISSET(data, &set)) {
            if ((len = NgRecvData(data, buf, sizeof(buf), hookname)) > 0) {
                /*printf("got %zd bytes from %s", len, hookname);
                for (int i = 0; i < len; ++i) {
                    if (i % 16 == 0) { printf ("\n"); }
                    printf(" %02x", buf[i]);
                }
                printf("\n"); */
                if (I_AM_CARP_MASTER && strcmp("pppoe", hookname) == 0) {
                    discovery_process_state(data, 1, buf, len, sizeof(buf));
                } else if (I_AM_CARP_MASTER && strcmp("ether", hookname) == 0) {
                    discovery_process_state(data, 0, buf, len, sizeof(buf));
                } else if (I_AM_CARP_MASTER && strcmp("ppp0", hookname) == 0) {
                    ppp_process_state(data, buf, len, sizeof(buf));
                }
            } else {
                syslog(LOG_ERR, "bad recv data");
                exit(1);
            }
        }
        if (FD_ISSET(routes, &set)) {
            if ((len = recv(routes, buf, sizeof(buf), 0)) > 0) {
                size_t i = 0;
                while (i < len) {
                    rt_msg = (struct rt_msghdr*)&buf[i];
                    if (i + rt_msg->rtm_msglen > len) {
                        syslog(LOG_ERR, "routing message past length of buffer: i: %ld, len: %ld, msg_len: %d",
                            i, len, rt_msg->rtm_msglen);
                        exit(1);
                    }
                    if (rt_msg->rtm_type == RTM_ADD || rt_msg->rtm_type == RTM_DELETE) {
                        if (rt_msg->rtm_addrs == (RTA_DST | RTA_GATEWAY | RTA_NETMASK)) {
                            if (rt_msg->rtm_msglen >= sizeof(*rt_msg) + sizeof(struct sockaddr_in)) {
                                struct sockaddr_in *dest, *gateway, *netmask;
                                dest = (struct sockaddr_in*)&buf[i+sizeof(*rt_msg)];
                                assert (i+sizeof(*rt_msg) + dest->sin_len + sizeof(struct sockaddr_in) <= rt_msg->rtm_msglen);
                                gateway = (struct sockaddr_in*)&buf[i+sizeof(*rt_msg) + dest->sin_len];
                                assert (i+sizeof(*rt_msg) + dest->sin_len + gateway->sin_len + sizeof(struct sockaddr_in) <= rt_msg->rtm_msglen);
                                netmask = (struct sockaddr_in*)&buf[i+sizeof(*rt_msg) + dest->sin_len + gateway->sin_len];
                                assert (i+sizeof(*rt_msg) + dest->sin_len + gateway->sin_len + netmask->sin_len <= rt_msg->rtm_msglen);
                                
                                if (netmask->sin_addr.s_addr == ntohl(INADDR_BROADCAST) && 
                                    dest->sin_addr.s_addr == CARP_ADDR.s_addr) {
                                    
                                    if (rt_msg->rtm_type == RTM_ADD && !I_AM_CARP_MASTER) {
                                        syslog(LOG_NOTICE, "I am CARP master");
                                        I_AM_CARP_MASTER = 1;
                                        new_state(PPP_CARP_MASTER);
                                    } else if (rt_msg->rtm_type == RTM_DELETE && I_AM_CARP_MASTER) {
                                        syslog(LOG_NOTICE, "I am not CARP master");
                                        I_AM_CARP_MASTER = 0;
                                        if (ppp_state != PPP_ZOMBIE && ppp_state != PPP_UP) {
                                            ppp_session = 0;
                                        }
                                        new_state(PPP_CLOSED);
                                    }
                                } else {
                                    char dest_ip[INET_ADDRSTRLEN], mask_ip[INET_ADDRSTRLEN];
                                    inet_ntoa_r(dest->sin_addr, dest_ip, sizeof(dest_ip));
                                    inet_ntoa_r(netmask->sin_addr, mask_ip, sizeof(mask_ip));
                                }
                            }
                        } 
                    }
                    i += rt_msg->rtm_msglen;
                }
            } else {
                syslog(LOG_ERR, "bad routes data");
                exit(1);
            }
        }
        if (FD_ISSET(peers, &set)) {
            struct sockaddr_in from = {0};
            socklen_t fromlen = sizeof(from);
            if ((len = recvfrom(peers, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen)) > 0) {
                if (from.sin_addr.s_addr == CARP_PEER.s_addr && from.sin_port == htons(PEER_PORT)) {
                    if (len == 1 && buf[0] == '?' && ppp_session != 0) { // query
                        send_session_to_peer();
                    } else if (!I_AM_CARP_MASTER && buf[0] == '!') { // set
                        uint16_t old_session = ppp_session;
                        assert(len == 3 + ETHER_ADDR_LEN + sizeof(ppp_my_ip.s_addr) + sizeof(ppp_peer_ip.s_addr));
                        bcopy(&buf[1], ppp_ether, ETHER_ADDR_LEN);
                        ppp_session = (buf[1 + ETHER_ADDR_LEN] << 8) | buf[2 + ETHER_ADDR_LEN];
                        bcopy(&buf[3 + ETHER_ADDR_LEN], &ppp_my_ip.s_addr, sizeof(ppp_my_ip.s_addr));
                        bcopy(&buf[3 + ETHER_ADDR_LEN + sizeof(ppp_my_ip.s_addr)], &ppp_peer_ip.s_addr, sizeof(ppp_peer_ip.s_addr));
                        if (old_session != ppp_session) {
                            syslog(LOG_NOTICE, "got session %d from peer", ppp_session);
                        }
                    }
                }    
            }        
        }
        ppp_tick();
    }
}

void ppp_tick() {
    u_char buf[MAX_BUF];
    time_t now = time(NULL);
    
    if (!I_AM_CARP_MASTER) {
        if (!ppp_session && now > ppp_time) {
            struct sockaddr_in to = {0};
            to.sin_family = AF_INET;
            to.sin_len = sizeof(to);
            to.sin_port = htons(PEER_PORT);
            to.sin_addr.s_addr = CARP_PEER.s_addr;
            buf[0] = '?';
            sendto(peers, buf, 1, 0, (struct sockaddr *)&to, sizeof(to));
            ppp_time = now;
        }
        return;
    }
    
    if (ppp_state == PPP_STARTING || ((ppp_state == PPP_LCP_SENT || ppp_state == PPP_LCP_ACK_SENT) && now > ppp_time)) {
        if (ppp_tries == 0) {
            ppp_session = 0;
            new_state(PPP_CLOSED);
            return;
        }
        --ppp_tries;
        buf[0] = buf[1] = 0; // link number
        buf[2] = 0xc0; buf[3] = 0x21; // LCP
        buf[4] = 1; // code: Configure-Request
        buf[5] = 1; // id: 1
        buf[6] = 0; buf[7] = 8;// length (big endian)
        buf[8] = 1; buf[9] = 4; buf[10] = MTU >> 8; buf[11] = MTU & 0xFF; // MRU MTU
        //printf ("sending config-request\n");
        NgSendData(data, "ppp0", buf, 12);
        if (ppp_state == PPP_STARTING) {
            new_state(PPP_LCP_SENT);
        }
        ppp_time = now;
    } else if (ppp_state == PPP_CHAP_SUCCESS || ((ppp_state == PPP_IPCP_SENT || ppp_state == PPP_IPCP_ACK_SENT) && now > ppp_time)) {
        if (ppp_tries == 0) {
            ppp_session = 0;
            new_state(PPP_CLOSED);
            return;
        }
        --ppp_tries;
        
        buf[0] = buf[1] = 0; // link number
        buf[2] = 0x80; buf[3] = 0x21; // IPCP
        buf[4] = 1; // code: Configure-Request
        buf[5] = 1; // id: 1
        buf[6] = 0; buf[7] = 10;// length (big endian)
        buf[8] = 3; buf[9] = 6;
        bcopy(&ppp_my_ip.s_addr, &buf[10], 4);
        //printf ("sending ipcp-request: %ld-%ld (%d)\n", ppp_time, now, ppp_state);
        NgSendData(data, "ppp0", buf, 14);
        
        if (ppp_state == PPP_CHAP_SUCCESS) {
            new_state(PPP_IPCP_SENT);
        }
        ppp_time = now;
    } else if (ppp_state == PPP_CLOSED && now > ppp_time) {
        if (ppp_tries == 0) {
            struct ngm_rmhook rmhook = {0};
            snprintf(rmhook.ourhook, sizeof(rmhook.ourhook), SESSION_HOOK);
            NgSendMsg(control, "pppoe:", NGM_GENERIC_COOKIE, NGM_RMHOOK, &rmhook, sizeof(rmhook));
        
            struct ngm_connect connect = {0};
            snprintf(connect.path, sizeof(connect.path), "ppp0:");
            snprintf(connect.ourhook, sizeof(connect.ourhook), SESSION_HOOK);
            snprintf(connect.peerhook, sizeof(connect.peerhook), "link0");
            send_or_die("connect ppp", control, "pppoe:", NGM_GENERIC_COOKIE, NGM_CONNECT, &connect, sizeof(connect));

            struct ngpppoe_init_data pppoe_init = {0};
            snprintf(pppoe_init.hook, sizeof(pppoe_init.hook), SESSION_HOOK);
            send_or_die("start pppoe session", control, "pppoe:", NGM_PPPOE_COOKIE, NGM_PPPOE_CONNECT, &pppoe_init, sizeof(pppoe_init));
            new_state(PPP_DISCOVERY);
        } else {
            --ppp_tries;
            ppp_time = now;
        }
    } else if ((ppp_state == PPP_ZOMBIE && now > ppp_time) || (ppp_state == PPP_UP && now > ppp_time + 5)) {
        // other side waits 50 seconds to close session
        if (ppp_tries == 0) {
            if (ppp_state == PPP_UP) {
                new_state(PPP_ZOMBIE);
            } else {
                ppp_session = 0;
                new_state(PPP_CLOSED);
            }
        } else {
            buf[0] = buf[1] = 0; // link number
            buf[2] = 0xc0; buf[3] = 0x21; // LCP
            buf[4] = 9; // code: Echo-Request
            buf[5] = 1; // id: 1
            buf[6] = 0; buf[7] = 8;// length (big endian)
            buf[8] = buf[9] = buf[10] = buf[11] = 0; // we have no magic number
            NgSendData(data, "ppp0", buf, 12);
            --ppp_tries;
            ppp_time = now;
        }
    } 
}

void ppp_process_state(int fd, u_char * data, size_t len, size_t buflen) {
    if (data[0] != 0 || data[1] != 0) {
        syslog(LOG_ERR, "multilink ppp?");
        exit(1);
    }
    if (len >= 8 && data[2] == 0xc0 && data[3] == 0x21 && 
        (len == ((data[6] << 8) | data[7]) + 4)) { // LCP

        if (data[4] == 1 && (ppp_state == PPP_LCP_SENT || ppp_state == PPP_LCP_ACK_RCVD)) { // Configure-Request
            int i = 8;
            while (i < len) {
                if ((data[i] == 1 && data[i + 1] == 4 && data[i + 2] == 5 && data[i + 3] == 0xd4) || // MRU
                    (data[i] == 3 && data[i + 1] == 5 && data[i + 2] == 0xc2 && data[i + 3] == 0x23 && data[i + 4] == 5) || // CHAP-MD5
                    (data[i] == 5 && data[i + 1] == 6)) { // Magic Number
                    
                    i += data[i + 1];
                } else {
                    syslog(LOG_ERR, "unknown LCP option");
                    exit(1);
                }
            }
            data[4] = 2;
            NgSendData(fd, "ppp0", data, len);
            if (ppp_state == PPP_LCP_SENT) {
                new_state(PPP_LCP_ACK_SENT);
            }
            if (ppp_state == PPP_LCP_ACK_RCVD) {
                new_state(PPP_CHAP);
            }
        } else if (data[4] == 2) { // Configure-Ack
            if (ppp_state == PPP_LCP_SENT) {
                new_state(PPP_LCP_ACK_RCVD);
            }
            if (ppp_state == PPP_LCP_ACK_SENT) {
                new_state(PPP_CHAP);
            }
        } else if (data[4] == 9) { // Echo-Request
            data[4] = 10;
            bzero(&data[8], 4); // We don't have a magic number
            NgSendData(fd, "ppp0", data, len);
        } else if (data[4] == 10) { // Echo-Reply
            if (ppp_state == PPP_ZOMBIE) {
                new_state(PPP_UP);
            }
            ppp_tries = TRIES;
            send_session_to_peer();
        }
    } else if (len >= 8 && data[2] == 0xc2 && data[3] == 0x23 && 
        (len == ((data[6] << 8) | data[7]) + 4)) { // CHAP
        
        if (data[4] == 1) { // Challenge
            // Assuming data is a large buffer, and username is not huge
            assert(buflen >= 5 + 16 + strlen(USER) + 4);
            
            MD5_CTX ctx;
            MD5Init(&ctx);
            MD5Update(&ctx, &data[5], 1); // Identifier
            MD5Update(&ctx, PASS, strlen(PASS));
            MD5Update(&ctx, &data[9], data[8]);
            MD5Final(&data[9], &ctx);
            data[4] = 2; // Rresponse
            data[8] = 16; // MD5 hash is 16 bytes
            bcopy(USER, &data[9 + 16], strlen(USER));
            len = 5 + 16 + strlen(USER);
            data[6] = len >> 8;
            data[7] = len & 0xFF;
            NgSendData(fd, "ppp0", data, len + 4);
        } else if (data[4] == 3) {
            if (ppp_state == PPP_CHAP) {
                new_state(PPP_CHAP_SUCCESS);
            }
        } else if (data[4] == 4) {
            syslog(LOG_ERR, "CHAP failure :(");
        }
    } else if (len >= 8 && data[2] == 0x80 && data[3] == 0x21 && 
        (len == ((data[6] << 8) | data[7]) + 4)) { // IPCP

        if (data[4] == 1 && (ppp_state == PPP_CHAP || ppp_state == PPP_CHAP_SUCCESS || ppp_state == PPP_IPCP_SENT || ppp_state == PPP_IPCP_ACK_RCVD)) { // Configure-Request
            int i = 8;
            while (i < len) {
                if (data[i] == 3 && data[i + 1] == 6) {
                    bcopy(&data[i+2], &ppp_peer_ip, 4);
                    
                    i += data[i + 1];
                } else {
                    syslog(LOG_ERR, "unknown IPCP option");
                    exit(1);
                }
            }
            data[4] = 2;
            NgSendData(fd, "ppp0", data, len);
            if (ppp_state == PPP_CHAP || ppp_state == PPP_CHAP_SUCCESS || ppp_state == PPP_IPCP_SENT) {
                new_state(PPP_IPCP_ACK_SENT);
            } else if (ppp_state == PPP_IPCP_ACK_RCVD) {
                new_state(PPP_UP);
            }
        } else if (data[4] == 2) { //Configure-Ack
            if (ppp_state == PPP_IPCP_SENT) {
                new_state(PPP_IPCP_ACK_RCVD);
            }
            if (ppp_state == PPP_IPCP_ACK_SENT) {
                new_state(PPP_UP);
            }
        } else if (data[4] == 3 && (ppp_state == PPP_IPCP_SENT || ppp_state == PPP_IPCP_ACK_SENT)) { // Configure-Nack
            int i = 8;
            while (i < len) {
                if (data[i] == 3 && data[i + 1] == 6) {
                    bcopy(&data[i+2], &ppp_my_ip, 4);
                    
                    i += data[i + 1];
                } else {
                    syslog(LOG_ERR, "unknown IPCP option");
                    exit(1);
                }
            }
            data[4] = 1;
            NgSendData(fd, "ppp0", data, len);
            ppp_time = time(NULL);
            ppp_tries = TRIES; // reset resend counter, cause we sent a new Configure-Request
        }
    }
}

void delete_default_route() {
    u_char buf[MAX_BUF];
    struct rt_msghdr *rt_msg = (struct rt_msghdr*) buf;
    bzero(rt_msg, sizeof(*rt_msg));
    rt_msg->rtm_type = RTM_DELETE;
    rt_msg->rtm_version = RTM_VERSION;
    rt_msg->rtm_addrs = (RTA_DST | RTA_NETMASK);
    rt_msg->rtm_flags =  RTF_UP | RTF_GATEWAY | RTF_STATIC;
    int i = sizeof(*rt_msg);
    struct sockaddr_in *sockaddr = (struct sockaddr_in *)&buf[i];
    bzero(sockaddr, sizeof(*sockaddr));
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = 0;
    i += sizeof(*sockaddr);
    sockaddr = (struct sockaddr_in*) &buf[i];
    bzero(sockaddr, sizeof(*sockaddr));
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = 0;
    i += sizeof(*sockaddr);
    rt_msg->rtm_msglen = i;

    if (write(routes, buf, i) == i) {
        syslog(LOG_NOTICE, "default route deleted");
    } else if (errno == ESRCH) {
        syslog(LOG_INFO, "default route already missing");
    } else {
        syslog(LOG_ERR, "couldn't delete default route: %m");
        exit(1);
    }
}

void set_default_route(struct in_addr *gateway) {
    u_char buf[MAX_BUF];
    struct rt_msghdr *rt_msg = (struct rt_msghdr*) buf;
    bzero(rt_msg, sizeof(*rt_msg));
    rt_msg->rtm_type = RTM_ADD;
    rt_msg->rtm_version = RTM_VERSION;
    rt_msg->rtm_addrs = (RTA_DST | RTA_GATEWAY | RTA_NETMASK);
    rt_msg->rtm_flags =  RTF_UP | RTF_GATEWAY | RTF_STATIC;
    int i = sizeof(*rt_msg);
    struct sockaddr_in *sockaddr = (struct sockaddr_in *)&buf[i];
    bzero(sockaddr, sizeof(*sockaddr));
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = 0;
    i += sizeof(*sockaddr);
    sockaddr = (struct sockaddr_in *)&buf[i];
    bzero(sockaddr, sizeof(*sockaddr));
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = gateway->s_addr;
    i += sizeof(*sockaddr);
    sockaddr = (struct sockaddr_in*) &buf[i];
    bzero(sockaddr, sizeof(*sockaddr));
    sockaddr->sin_len = sizeof(*sockaddr);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = 0;
    i += sizeof(*sockaddr);
    rt_msg->rtm_msglen = i;

    if (write(routes, buf, i) == i) {
        syslog(LOG_NOTICE, "default route added");
    } else if (errno == EEXIST) {
        rt_msg->rtm_type = RTM_CHANGE;
        if (write(routes, buf, i) == i) {
            syslog(LOG_NOTICE, "default route changed");
        } else {
            syslog(LOG_ERR, "couldn't change default route: %m");
            exit(1);
        }
    } else {
        char ip[INET_ADDRSTRLEN];
        inet_ntoa_r(*gateway, ip, sizeof(ip));
        syslog(LOG_ERR, "couldn't add default route %s: %m", ip);
        exit(1);
    }
}

void new_state (int s) {
    switch(s) {
        case PPP_DISCOVERY:
            assert(ppp_state == PPP_CLOSED);
            ppp_state = PPP_DISCOVERY;
            break;
        case PPP_STARTING:
            assert(ppp_state == PPP_DISCOVERY);
            ppp_state = PPP_STARTING;
            ppp_tries = TRIES;
            ppp_time = 0;
            break;
        case PPP_LCP_SENT:
            assert (ppp_state == PPP_STARTING);
            ppp_state = PPP_LCP_SENT;
            break;
        case PPP_LCP_ACK_SENT:
            assert (ppp_state == PPP_LCP_SENT);
            ppp_state = PPP_LCP_ACK_SENT;
            break;
        case PPP_LCP_ACK_RCVD:
            assert(ppp_state == PPP_LCP_SENT);
            ppp_state = PPP_LCP_ACK_RCVD;
            ppp_tries = TRIES;
            break;
        case PPP_CHAP:
            assert (ppp_state == PPP_LCP_ACK_RCVD || ppp_state == PPP_LCP_ACK_SENT);
            ppp_state = PPP_CHAP;
            break;
        case PPP_CHAP_SUCCESS:
            assert(ppp_state == PPP_CHAP);
            ppp_state = PPP_CHAP_SUCCESS;
            ppp_tries = TRIES;
            break;
        case PPP_IPCP_SENT:
            assert (ppp_state == PPP_CHAP_SUCCESS);
            ppp_state = PPP_IPCP_SENT;
            break;
        case PPP_IPCP_ACK_SENT:
            assert(ppp_state == PPP_CHAP || ppp_state == PPP_CHAP_SUCCESS || ppp_state == PPP_IPCP_SENT);
            if (ppp_state != PPP_IPCP_SENT) {
                ppp_time = 0; // force "resend" of IPCP configure-request
                ppp_tries = TRIES;
            }
            ppp_state = PPP_IPCP_ACK_SENT;
            break;
        case PPP_IPCP_ACK_RCVD:
            assert(ppp_state == PPP_IPCP_SENT);
            ppp_state = PPP_IPCP_ACK_RCVD;
            ppp_tries = TRIES;
            break;
        case PPP_UP:
            assert(ppp_state == PPP_IPCP_ACK_RCVD || ppp_state == PPP_IPCP_ACK_SENT || ppp_state == PPP_ZOMBIE);
            FILE * state_file = fopen ("/var/db/ppp_thing.state.tmp", "w");
            char my_ip[INET_ADDRSTRLEN], peer_ip[INET_ADDRSTRLEN];
            inet_ntoa_r(ppp_my_ip, my_ip, sizeof(my_ip));
            inet_ntoa_r(ppp_peer_ip, peer_ip, sizeof(peer_ip));
            
            if (state_file != NULL) {
                fprintf(state_file, "%x:%x:%x:%x:%x:%x\n%u\n%s\n%s\n",
                    ppp_ether[0], ppp_ether[1], ppp_ether[2],
                    ppp_ether[3], ppp_ether[4], ppp_ether[5],
                    ppp_session, my_ip, peer_ip
                );
                if (fclose(state_file) == 0) {
                    rename("/var/db/ppp_thing.state.tmp", "/var/db/ppp_thing.state");
                }
            }
            
            struct ifreq ifr;

            bzero(&ifr, sizeof(ifr));
            (void) strlcpy(ifr.ifr_name, "ng0", sizeof(ifr.ifr_name));
            ifr.ifr_mtu = MTU;
            if (ioctl(ioctls, SIOCSIFMTU, (caddr_t)&ifr) < 0) {
                syslog(LOG_ERR, "ioctl SIOCSIFMTU (set mtu): %m");;
                exit(1);
            }
            
            bzero(&ifr, sizeof(ifr));
            (void) strlcpy(ifr.ifr_name, "ng0", sizeof(ifr.ifr_name));
            if (ioctl(ioctls, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
                syslog(LOG_ERR, "ioctl SIOCGIFFLAGS: %m");;
                exit(1);
            }
            uint32_t flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
            flags |= IFF_UP;
            ifr.ifr_flags = flags & 0xffff;
            ifr.ifr_flagshigh = flags >> 16;
            if (ioctl(ioctls, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
                syslog(LOG_ERR, "ioctl (SIOCSIFFLAGS): %m");;
                exit(1);
            }

            syslog(LOG_NOTICE, "PPP UP! %s <-> %s mtu %d",
                my_ip, peer_ip, MTU);

            bzero(&ifr, sizeof(ifr));
            strlcpy(ifr.ifr_name, "ng0", sizeof ifr.ifr_name);
            int ret = ioctl(ioctls, SIOCDIFADDR, (caddr_t)&ifr);
            if (ret < 0) {
                if (errno == EADDRNOTAVAIL) {
                /* means no previous address for interface */
                } else {
                    syslog(LOG_ERR, "ioctl (SIOCDIFADDR): %m");;
                    exit(1);
                }
            }

            struct in_aliasreq ifra;
            bzero(&ifra, sizeof(ifra));
            (void) strlcpy(ifra.ifra_name, "ng0", sizeof(ifra.ifra_name));
            ifra.ifra_addr.sin_len = ifra.ifra_dstaddr.sin_len = ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
            ifra.ifra_addr.sin_family = ifra.ifra_dstaddr.sin_family = ifra.ifra_mask.sin_family = AF_INET;
            
            ifra.ifra_addr.sin_addr.s_addr = ppp_my_ip.s_addr;
            ifra.ifra_dstaddr.sin_addr.s_addr = ppp_peer_ip.s_addr;
            ifra.ifra_mask.sin_addr.s_addr = INADDR_BROADCAST;
            
            // tweak config so it's more useful!
            ifra.ifra_addr.sin_addr.s_addr = CARP_ME.s_addr;
                
            unsigned long req = SIOCAIFADDR;
            if (ioctl(ioctls, req, (caddr_t)&ifra) < 0) {
                syslog(LOG_ERR, "ioctl SIOCAIFADDR (set tunnel address ng0): %m");;
                exit(1);
            }
            
            (void) strlcpy(ifra.ifra_name, "ng1", sizeof(ifra.ifra_name));
            ifra.ifra_addr.sin_addr.s_addr = ppp_my_ip.s_addr;
            ifra.ifra_dstaddr.sin_addr.s_addr = ppp_my_ip.s_addr;
            ifra.ifra_mask.sin_addr.s_addr = INADDR_BROADCAST;
            if (ioctl(ioctls, req, (caddr_t)&ifra) < 0) {
                syslog(LOG_ERR, "ioctl SIOCAIFADDR (set tunnel address ng1): %m");;
                exit(1);
            }
            
            syslog(LOG_INFO, "session %u, ether %x:%x:%x:%x:%x:%x", ppp_session,
                ppp_ether[0], ppp_ether[1], ppp_ether[2],
                ppp_ether[3], ppp_ether[4], ppp_ether[5]);
            
            send_session_to_peer();
            set_default_route(&ppp_peer_ip);
            ppp_state = PPP_UP;
            ppp_tries = TRIES;
            break;
        case PPP_CLOSED: {
            struct ifreq ifr;
            bzero(&ifr, sizeof(ifr));

            (void) strlcpy(ifr.ifr_name, "ng0", sizeof(ifr.ifr_name));
            if (ioctl(ioctls, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
                syslog(LOG_ERR, "ioctl SIOCGIFFLAGS down: %m");;
                exit(1);
            }
            uint32_t flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
            flags &= ~IFF_UP;
            ifr.ifr_flags = flags & 0xffff;
            ifr.ifr_flagshigh = flags >> 16;
            if (ioctl(ioctls, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
                syslog(LOG_ERR, "ioctl (SIOCSIFFLAGS) down: %m");;
                exit(1);
            }
            bzero(&ifr, sizeof(ifr));
            strlcpy(ifr.ifr_name, "ng0", sizeof ifr.ifr_name);
            int ret = ioctl(ioctls, SIOCDIFADDR, (caddr_t)&ifr);
            if (ret < 0) {
                if (errno == EADDRNOTAVAIL) {
                /* means no previous address for interface */
                } else {
                    syslog(LOG_ERR, "ioctl (SIOCDIFADDR): %m");;
                    exit(1);
                }
            }

            strlcpy(ifr.ifr_name, "ng1", sizeof ifr.ifr_name);
            ret = ioctl(ioctls, SIOCDIFADDR, (caddr_t)&ifr);
            if (ret < 0) {
                if (errno == EADDRNOTAVAIL) {
                /* means no previous address for interface */
                } else {
                    syslog(LOG_ERR, "ioctl (SIOCDIFADDR): %m");;
                    exit(1);
                }
            }
        
            struct ngm_rmhook rmhook = {0};
            snprintf(rmhook.ourhook, sizeof(rmhook.ourhook), SESSION_HOOK);
            NgSendMsg(control, "pppoe:", NGM_GENERIC_COOKIE, NGM_RMHOOK, &rmhook, sizeof(rmhook));
            
            if (I_AM_CARP_MASTER) {
                delete_default_route();
                send_session_to_peer();
            } else {
                set_default_route(&CARP_PEER);
            }

            if (ppp_state == PPP_ZOMBIE || ppp_state == PPP_UP || ppp_state == PPP_CLOSED) {
                ppp_tries = 0;
            } else {
                ppp_tries = TRIES;
            }
            ppp_state = PPP_CLOSED;
            break; }
        case PPP_ZOMBIE:
            assert(ppp_state == PPP_DISCOVERY || ppp_state == PPP_UP);
            ppp_tries = TRIES;
            if (ppp_state == PPP_DISCOVERY) {
                // wait less if resuming a session
                ppp_tries >>= 1; 
            }
            ppp_state = PPP_ZOMBIE;
            break;
        case PPP_CARP_MASTER:
            assert(ppp_state == PPP_CLOSED);
            ppp_tries = 0;
            ppp_time = 0;
            break;
    }
}        

void discovery_process_state(int fd, int from_client, u_char * data, size_t len, size_t buflen) {
    if (from_client) {
        if (ppp_session && // we have a session to resume
            data[14] == 0x11 && data[15] == 9 && // Discovery Initiation
            (len - 20) == ((data[18] << 8) + data[19])) { // length equals packet length minus headers
            
            bcopy(&data[ETHER_ADDR_LEN], &data[0], ETHER_ADDR_LEN); // copy source mac to dest
            bcopy(ppp_ether, &data[ETHER_ADDR_LEN], ETHER_ADDR_LEN);// set src mac to servers
            data[15] = 7; // Discovery Offer
            int has_ac_name = 0;
            int i = 20;
            while (i + 4 < len) {
                if (data[i] == 1 && data[i + 1] == 2) {
                    has_ac_name = 1;
                    break;
                }
                i += (data[i + 2] << 8) + data[i + 3];
            }
            if (!has_ac_name && buflen > len + 10) {
                data[len] = 1; data[len + 1] = 2;
                data[len + 2] = 0; data[len + 3] = 8;
                
                bcopy("resume", &data[len + 4], 6);
            }
            NgSendData(fd, "pppoe", data, len + 10);
        } else if (ppp_session && data[14] == 0x11 && data[15] == 0x19) { // Request
            data[15] = 0x65; // Session-confirmation
            data[16] = ppp_session >> 8;
            data[17] = ppp_session & 0xFF;
            NgSendData(fd, "pppoe", data, len);
        } else if (data[14] == 0x11 && data[15] == 0xa7) { // Terminate
            // don't proxy these
        } else {
            // proxy to real server
            NgSendData(fd, "ether", data, len);
        }
    } else {
        if (len >= 20 && bcmp(data, ETHER_ADDR, ETHER_ADDR_LEN) == 0 && // sent to us, long enough
            data[12] == 0x88 && data[13] == 0x63 && // EtherType
            data[14] == 0x11 && data[15] == 0x65 && // version/type, code = session-confirmation
            !(data[16] == 0 && data[17] == 0) && // session is set
            (len - 20) == ((data[18] << 8) + data[19])) { // length equals packet length minus headers
        
            probable_session = (data[16] << 8) + data[17];
            bcopy(&data[6], probable_ether, ETHER_ADDR_LEN);
        }
        NgSendData(fd, "pppoe", data, len);
    }
}

void load_state() {
    FILE * state_file = fopen("/var/db/ppp_thing.state", "r");
    char my_ip[INET_ADDRSTRLEN];
    char peer_ip[INET_ADDRSTRLEN];
    int line = 0;
    while (line < 4 && state_file != NULL && !feof(state_file)) {
        switch(line) {
            case 0:
                fscanf(state_file, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                    &ppp_ether[0], &ppp_ether[1], &ppp_ether[2],
                    &ppp_ether[3], &ppp_ether[4], &ppp_ether[5]);
                break;
            case 1:
                fscanf(state_file, "%hu\n", &ppp_session);
                break;
            case 2:
                fgets(my_ip, sizeof(my_ip), state_file);
                break;
            case 3:
                fgets(peer_ip, sizeof(peer_ip), state_file);
                break;
        }
        ++line;
    }
    if (!inet_aton(my_ip, &ppp_my_ip) || !inet_aton(peer_ip, &ppp_peer_ip)) {
        ppp_session = 0;
    }
    if (state_file != NULL) {
        fclose(state_file);
    }
}    

void load_config() {
    FILE * config_file = fopen("/usr/local/etc/ppp_thing.conf", "r");
    int line = 0;
    char carp[INET_ADDRSTRLEN], me[INET_ADDRSTRLEN], peer[INET_ADDRSTRLEN];
    
    while (line < 8 && config_file != NULL && !feof(config_file)) {
        switch(line) {
            case 0:
                fgets(ETHER_INTERFACE, sizeof(ETHER_INTERFACE), config_file);
                *strchrnul(ETHER_INTERFACE, '\n') = 0;
                break;
            case 1:
                fscanf(config_file, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                    &ETHER_ADDR[0], &ETHER_ADDR[1], &ETHER_ADDR[2],
                    &ETHER_ADDR[3], &ETHER_ADDR[4], &ETHER_ADDR[5]);
                break; 
            case 2:
                fgets(USER, sizeof(USER), config_file);
                *strchrnul(USER, '\n') = 0;
                break;
            case 3:
                fgets(PASS, sizeof(PASS), config_file);
                *strchrnul(PASS, '\n') = 0;
                break;
            case 4:
                fscanf(config_file, "%hd\n", &MTU);
                break;
            case 5:
                fgets(carp, sizeof(carp), config_file);
                break;
            case 6:
                fgets(me, sizeof(me), config_file);
                break;
            case 7:
                fgets(peer, sizeof(peer), config_file);
                break;
        }
        ++line;
    }
    
    if (!MTU || !inet_aton(carp, &CARP_ADDR) || !inet_aton(me, &CARP_ME) || !inet_aton(peer, &CARP_PEER)) {
        syslog(LOG_ERR, "invalid config file");
        printf("/usr/local/etc/ppp_thing.conf must look like:\ninterface\nMAC address\nuser\npassword\nMTU\nCARP address to monitor\nMY ADDRESS\nCARP peer\n");
        exit(1);
    }
    inet_ntoa_r(CARP_ADDR, carp, sizeof(carp));
    inet_ntoa_r(CARP_ME, me, sizeof(me));
    inet_ntoa_r(CARP_PEER, peer, sizeof(peer));
    syslog(LOG_INFO, "interface %s (%x:%x:%x:%x:%x:%x), user %s, pass %s, mtu %d, carp %s, me %s, peer %s",
        ETHER_INTERFACE, ETHER_ADDR[0], ETHER_ADDR[1], ETHER_ADDR[2],
        ETHER_ADDR[3], ETHER_ADDR[4], ETHER_ADDR[5], USER, PASS, MTU,
        carp, me, peer);
}    

void send_session_to_peer() {
    u_char buf[3 + ETHER_ADDR_LEN + sizeof(ppp_my_ip.s_addr) + sizeof(ppp_peer_ip.s_addr)];
    buf[0] = '!';
    bcopy(ppp_ether, &buf[1], ETHER_ADDR_LEN);
    buf[1 + ETHER_ADDR_LEN] = ppp_session >> 8;
    buf[2 + ETHER_ADDR_LEN] = ppp_session & 0xFF;
    bcopy(&ppp_my_ip.s_addr, &buf[3 + ETHER_ADDR_LEN], sizeof(ppp_my_ip.s_addr));
    bcopy(&ppp_peer_ip.s_addr, &buf[3 + ETHER_ADDR_LEN + sizeof(ppp_my_ip.s_addr)], sizeof(ppp_peer_ip.s_addr));
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET;
    to.sin_len = sizeof(to);
    to.sin_port = htons(PEER_PORT);
    to.sin_addr.s_addr = CARP_PEER.s_addr;
    sendto(peers, buf, sizeof(buf), 0, (struct sockaddr *)&to, sizeof(to));
}
