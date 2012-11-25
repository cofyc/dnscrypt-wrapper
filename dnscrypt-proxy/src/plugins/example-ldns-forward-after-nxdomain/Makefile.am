
pkglib_LTLIBRARIES = \
	libdcplugin_example_ldns_forward_after_nxdomain.la

libdcplugin_example_ldns_forward_after_nxdomain_la_LIBTOOLFLAGS = --tag=disable-static

libdcplugin_example_ldns_forward_after_nxdomain_la_SOURCES = \
	example-ldns-forward-after-nxdomain.c

libdcplugin_example_ldns_forward_after_nxdomain_la_LIBADD = @LDNS_LIBS@

libdcplugin_example_ldns_forward_after_nxdomain_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-avoid-version \
	-export-dynamic \
	-module \
	-no-undefined

libdcplugin_example_ldns_forward_after_nxdomain_la_CPPFLAGS = \
	$(LTDLINCL) \
	-I../../include
