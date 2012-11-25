
sbin_PROGRAMS = \
	dnscrypt-proxy

dnscrypt_proxy_SOURCES = \
	app.c \
	app.h \
	cert.c \
	cert.h \
	cert_p.h \
	dnscrypt.c \
	dnscrypt.h \
	dnscrypt_client.c \
	dnscrypt_client.h \
	dnscrypt_proxy.h \
	edns.c \
	edns.h \
	getpwnam.h \
	logger.c \
	logger.h \
	options.c \
	options.h \
	pathnames.h \
	pid_file.c \
	pid_file.h \
	probes_dnscrypt_proxy.d \
	probes_no_dtrace.h \
	safe_rw.c \
	safe_rw.h \
	salsa20_random.c \
	salsa20_random.h \
	sandboxes.c \
	sandboxes.h \
	stack_trace.c \
	stack_trace.h \
	tcp_request.c \
	tcp_request.h \
	tcp_request_p.h \
	udp_request.c \
	udp_request.h \
	udp_request_p.h \
	utils.c \
	utils.h \
	windows_service.c \
	windows_service.h

AM_CFLAGS = @CWFLAGS@

AM_CPPFLAGS = \
	-I../ext \
	-I../libevent/include \
	-I../@NACL_PATH@/include/local

dnscrypt_proxy_LDADD = \
	../libevent/libevent_extra.la \
	../libevent/libevent_core.la \
	../@NACL_PATH@/lib/local/libnacl.a

dnscrypt_proxy_DEPENDENCIES = \
	../libevent/libevent_extra.la \
	../libevent/libevent_core.la \
	../libnacl/.done

BUILT_SOURCES = \
	../libnacl/.done \
	probes.h

../libnacl/.done:
	cd ../libnacl && $(MAKE) $(AM_MAKEFLAGS)

probes.h: @PROBES_SOURCE@
	cat @PROBES_SOURCE@ > $@

probes_dnscrypt_proxy.h: probes_dnscrypt_proxy.d
	@DTRACE@ -o $@ -h -s probes_dnscrypt_proxy.d

CLEANFILES = \
	probes.h \
	probes_dnscrypt_proxy.h

if PLUGINS

AM_CPPFLAGS += \
	$(LTDLINCL) \
	-I../include \
	-DPLUGINS_ROOT=\"$(pkglibdir)/\"

dnscrypt_proxy_LDADD += $(LIBLTDL)
dnscrypt_proxy_DEPENDENCIES += $(LTDLDEPS)

dnscrypt_proxy_SOURCES += \
	plugin_options.c \
	plugin_options.h \
	plugin_support.c \
	plugin_support.h \
	plugin_support_p.h

endif
