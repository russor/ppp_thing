# ppp_thing
> A poorly written, minimum viable PPPoE client with session handoff between redundant FreeBSD routers 

ppp_thing allows you to move a PPPoE session between two FreeBSD routers,
based on which router is master for a configured CARP address. This can be
combined with pfsync to communicate NAT tables and provide a seamless
failover in case of hardware failure or planned maintenance.

Session data is kept in ```/var/db/ppp_thing.state``` to be used if the
daemon restarts. Maybe useful for reboots on a single host, if your system
restarts faster than the Access Concentrator times out the session.

## Installation

```
make
make install
```

add a config in ```/usr/local/etc/ppp_thing.conf```; this is a simple line
oriented config file that looks like:

```
Interface where PPPoE runs
xx:xx:xx:xx:xx:xx <- mac address to use
username
password
MTU <- probably 1492
a.b.c.d <- CARP address to watch
e.f.g.h <- local address
i.j.k.l <- peer address
```

The mac address should be different from the physical address of the two
peer routers; because whichever peer is master for the CARP address will use
it for the PPPoE session. See https://en.wikipedia.org/wiki/MAC_address#Universal_vs._local_(U/L_bit)
for guidance on picking a locally administered mac address.

The local address is assigned to the ppp interface (ng0), rather than the
negotiated address; that way connections initiated from the active router
can be routed through the peer when the CARP address fails over, and the
peer becomes the active router. The negotiated address is assigned to a
dummy interface (ng1), which can be used for configuring PF nat.

Once configured ```service ppp_thing onestart``` should start it up. You
will need to load the ```ng_ether``` module, or include it in your kernel.

## Meta

Richard Russo - pppoe@enslaves.us

Distributed under the BSD license. See ``LICENSE`` for more information.

[https://github.com/russor/ppp_thing](https://github.com/russor/ppp_thing)

## Contributing

Please send me an email to discuss before starting work. I've kept things
pretty simple, because this is good enough for me, and it's 2021. Ideally,
PPPoE should be dead or dying, not seeing new development.

However, if you want to make some protocol correctness mentioned in the
header of the code changes, or your ISP is enlightned enough to support
PPP-Max-Payload, and you've got a patch to make that work; that sounds good.

Or if you found a crash, or using unitialized memory etc, please report (or
patch).

If you really want a good PPPoE client,
[https://sourceforge.net/projects/mpd/](mpd) looks like a good choice; but
it doesn't have a way (that I could see) to share a session between two
peers.

