# The default target
all:: 

CC = cc
RM = rm -rf

EXTRA_CFLAGS = # dynamically added/remoted
CFLAGS = -std=c99 -pedantic -Wall $(EXTRA_CFLAGS) -Ilibevent/include
LDFLAGS = -lm
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

LIB_H = dnscrypt.h udp_request.h edns.h argparse/argparse.h logger.h

LIB_OBJS += dnscrypt.o
LIB_OBJS += udp_request.o
LIB_OBJS += edns.o
LIB_OBJS += logger.o
LIB_OBJS += main.o
LIB_OBJS += argparse/argparse.o

LDADD += libnacl/build/localhost/lib/local/libnacl.a
LDADD += libevent/.libs/libevent.a

argparse/argparse.o:
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
	find . -name '*.[oa]' | xargs $(RM)

.PHONY: all install uninstall clean test
