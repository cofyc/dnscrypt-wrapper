# The default target
all:: 

CC = cc
RM = rm -rf

EXTRA_CFLAGS = # dynamically added/remoted
CFLAGS = -O2 -std=c99 -pedantic -Wall $(EXTRA_CFLAGS) -Ilibevent/include -Ilibnacl/build/localhost/include/local
LDFLAGS = -lm
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

LIB_H = dnscrypt.h udp_request.h edns.h argparse/argparse.h logger.h

LIB_OBJS += dnscrypt.o
LIB_OBJS += udp_request.o
LIB_OBJS += dnscrypt_server.o
LIB_OBJS += edns.o
LIB_OBJS += logger.o
LIB_OBJS += main.o
LIB_OBJS += rfc1035.o
LIB_OBJS += argparse/argparse.o
LIB_OBJS += salsa20_random.o
LIB_OBJS += safe_rw.o
LIB_OBJS += cert.o

LDADD += libnacl/build/localhost/lib/local/libnacl.a
LDADD += libevent/.libs/libevent.a

argparse/.git:
	@git submodule update --init

argparse/argparse.o: argparse/.git
	@make -C argparse argparse.o

libnacl/build/localhost/lib/local/libnacl.a:
	@make -C libnacl

libevent/.libs/libevent.a:
	@make -C libevent

all:: dnscrypt-wrapper

dnscrypt-wrapper: $(LIB_OBJS) $(LDADD)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^

install: all
	install -p -m 755 dnscrypt-wrapper $(BINDIR)

uninstall:
	$(RM) $(BINDIR)/dnscrypt-wrapper

clean:
	$(RM) dnscrypt-wrapper
	$(RM) *.o
	$(RM) libnacl/.done 

.PHONY: all install uninstall clean test
