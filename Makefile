PROG=ppp_thing
SRCS=ppp_thing.c
LDADD=-lnetgraph -lmd
MAN=
DEBUG_FLAGS=-g
DESTDIR=/usr/local/bin

install: $(PROG)
	install -o root -g wheel -m 500 ppp_thing /usr/local/bin/ppp_thing
	install -o root -g wheel -m 755 $(PROG).rc /usr/local/etc/rc.d/$(PROG)

.include <bsd.prog.mk>

