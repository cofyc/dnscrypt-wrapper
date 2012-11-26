# dnscrypt-wrapper Makefile
#
# The default target
all::

CC = cc
RM = rm -rf
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

FINAL_CFLAGS = $(CFLAGS) -O2 -std=c99 -pedantic -Wall -Idnscrypt-proxy/src/libevent/include -Idnscrypt-proxy/src/libnacl/build/localhost/include/local
FINAL_LDFLAGS = $(LDFLAGS) -lm

ifeq ($(uname_S),Linux)
	FINAL_LDFLAGS += -lrt
endif

LIB_H = dnscrypt.h udp_request.h edns.h logger.h dnscrypt-proxy/src/libevent/include/event2/event.h dnscrypt-proxy/src/libnacl/build/localhost/include/local/crypto_box.h

LIB_OBJS += dnscrypt.o
LIB_OBJS += udp_request.o
LIB_OBJS += tcp_request.o
LIB_OBJS += edns.o
LIB_OBJS += logger.o
LIB_OBJS += main.o
LIB_OBJS += rfc1035.o
LIB_OBJS += salsa20_random.o
LIB_OBJS += safe_rw.o
LIB_OBJS += cert.o
LIB_OBJS += pidfile.o

LDADD += argparse/argparse.o
LDADD += dnscrypt-proxy/src/libnacl/build/localhost/lib/local/libnacl.a
LDADD += dnscrypt-proxy/src/libevent/.libs/libevent.a

argparse/argparse.o: argparse/argparse.h
	@make -C argparse argparse.o

dnscrypt-proxy/src/libevent/include/event2/event.h: dnscrypt-proxy/src/libevent/.libs/libevent.a
dnscrypt-proxy/src/libnacl/build/localhost/include/local/crypto_box.h: dnscrypt-proxy/src/libnacl/build/localhost/lib/local/libnacl.a

dnscrypt-proxy/src/libnacl/Makefile dnscrypt-proxy/src/libevent/Makefile: 
	cd dnscrypt-proxy && ./autogen.sh && ./configure

dnscrypt-proxy/src/libnacl/build/localhost/lib/local/libnacl.a: dnscrypt-proxy/src/libnacl/Makefile
	make -C dnscrypt-proxy/src/libevent

dnscrypt-proxy/src/libevent/.libs/libevent.a: dnscrypt-proxy/src/libevent/Makefile
	make -C dnscrypt-proxy/src/libnacl

$(LIB_OBJS): $(LIB_H)

all:: dnscrypt-wrapper

%.o: %.c
	$(CC) $(FINAL_CFLAGS) -c $<

main.o: version.h

dnscrypt-wrapper: $(LIB_OBJS) $(LDADD)
	$(CC) $(FINAL_CFLAGS) -o $@ $^ $(FINAL_LDFLAGS)

install: all
	install -p -m 755 dnscrypt-wrapper $(BINDIR)

uninstall:
	$(RM) $(BINDIR)/dnscrypt-wrapper

clean:
	$(RM) dnscrypt-wrapper
	$(RM) $(LIB_OBJS)

.PHONY: all install uninstall clean
