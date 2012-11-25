
bin_PROGRAMS = \
	hostip

hostip_SOURCES = \
	app.c \
	app.h \
	options.c \
	options.h

AM_CFLAGS = @CWFLAGS@

AM_CPPFLAGS = \
	-I../libevent/include

hostip_LDADD = \
	../libevent/libevent_extra.la \
	../libevent/libevent_core.la
