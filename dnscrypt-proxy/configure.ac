AC_PREREQ([2.61])
AC_INIT([dnscrypt-proxy],[1.2.0],[http://dnscrypt.org])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([libltdl/config])
AC_CONFIG_SRCDIR([src/proxy/app.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SUBDIRS([src/libevent])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.9 dist-bzip2 tar-ustar])
AM_MAINTAINER_MODE
AM_DEP_TRACK

AC_SUBST(VERSION)
ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

LX_CFLAGS=${CFLAGS-NONE}
AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
CPPFLAGS="$CPPFLAGS -D_FORTIFY_SOURCE=2"

AS_IF([test "$cross_compiling" != no],
  AC_DEFINE(CROSS_COMPILING,,[define if you are cross-compiling])
)

AX_CHECK_COMPILE_FLAG([-fPIC], [
  AX_CHECK_LINK_FLAG([-fPIC],
    [CFLAGS="$CFLAGS -fPIC"]
  )
])

AS_IF([test "$enable_pie" != "no"],[
  AX_CHECK_COMPILE_FLAG([-fPIE], [
    AX_CHECK_LINK_FLAG([-fPIE],
      [AX_CHECK_LINK_FLAG([-pie],
        [CFLAGS="$CFLAGS -fPIE"
         LDFLAGS="$LDFLAGS -pie"])
    ])
  ])
])

AX_CHECK_COMPILE_FLAG([-fcatch-undefined-c99-behavior],
  [CFLAGS="$CFLAGS -fcatch-undefined-c99-behavior"],
  [AX_CHECK_COMPILE_FLAG([-fwrapv], [CFLAGS="$CFLAGS -fwrapv"])]
)
AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing], [CFLAGS="$CFLAGS -fno-strict-aliasing"])
AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [CFLAGS="$CFLAGS -fno-strict-overflow"])

case $host_os in
  cygwin* | mingw* | pw32* | cegcc*)
    AX_CHECK_LINK_FLAG([-Wl,--dynamicbase], [LDFLAGS="$LDFLAGS -Wl,--dynamicbase"])
    AX_CHECK_LINK_FLAG([-Wl,--nxcompat], [LDFLAGS="$LDFLAGS -Wl,--nxcompat"])
    AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [
      AX_CHECK_LINK_FLAG([-fstack-protector-all],
        [CFLAGS="$CFLAGS -fstack-protector-all"]
      )
    ])
  ;;
  dragonfly*)
    AX_CHECK_COMPILE_FLAG([-fstack-protector], [
      AX_CHECK_LINK_FLAG([-fstack-protector],
        [CFLAGS="$CFLAGS -fstack-protector"]
      )
    ])
  ;;
  *)
    AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [
      AX_CHECK_LINK_FLAG([-fstack-protector-all],
        [CFLAGS="$CFLAGS -fstack-protector-all"]
      )
    ])
  ;;
esac

AX_CHECK_COMPILE_FLAG([-Wbounded], [CFLAGS="$CFLAGS -Wbounded"])
AX_CHECK_COMPILE_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"])
AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"])
AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [CFLAGS="$CFLAGS -Wdiv-by-zero"])

AC_ARG_VAR([CWFLAGS], [define to compilation flags for generating extra warnings])

AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wall], [CWFLAGS="$CWFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wextra], [CWFLAGS="$CWFLAGS -Wextra"])

AC_MSG_CHECKING(for clang)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
#ifndef __clang__
be sad
#endif
]])],
  [AC_MSG_RESULT(yes)
   AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wno-unknown-warning-option],
  [CWFLAGS="$CWFLAGS -Wno-unknown-warning-option"])],
  [AC_MSG_RESULT(no)
])

AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wbad-function-cast], [CWFLAGS="$CWFLAGS -Wbad-function-cast"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wcast-align], [CWFLAGS="$CWFLAGS -Wcast-align"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wcast-qual], [CWFLAGS="$CWFLAGS -Wcast-qual"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wchar-subscripts], [CWFLAGS="$CWFLAGS -Wchar-subscripts"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wcomment], [CWFLAGS="$CWFLAGS -Wcomment"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wfloat-equal], [CWFLAGS="$CWFLAGS -Wfloat-equal"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wformat=2], [CWFLAGS="$CWFLAGS -Wformat=2"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wimplicit], [CWFLAGS="$CWFLAGS -Wimplicit"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wmissing-declarations], [CWFLAGS="$CWFLAGS -Wmissing-declarations"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wmissing-prototypes], [CWFLAGS="$CWFLAGS -Wmissing-prototypes"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wnormalized=id], [CWFLAGS="$CWFLAGS -Wnormalized=id"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Woverride-init], [CWFLAGS="$CWFLAGS -Woverride-init"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wparentheses], [CWFLAGS="$CWFLAGS -Wparentheses"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wpointer-arith], [CWFLAGS="$CWFLAGS -Wpointer-arith"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wredundant-decls], [CWFLAGS="$CWFLAGS -Wredundant-decls"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wstrict-prototypes], [CWFLAGS="$CWFLAGS -Wstrict-prototypes"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wswitch-enum], [CWFLAGS="$CWFLAGS -Wswitch-enum"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wvariable-decl], [CWFLAGS="$CWFLAGS -Wvariable-decl"])

AX_CHECK_LINK_FLAG([-Wl,-z,relro], [LDFLAGS="$LDFLAGS -Wl,-z,relro"])
AX_CHECK_LINK_FLAG([-Wl,-z,now], [LDFLAGS="$LDFLAGS -Wl,-z,now"])
AX_CHECK_LINK_FLAG([-Wl,-z,noexecstack], [LDFLAGS="$LDFLAGS -Wl,-z,noexecstack"])

LT_INIT
AC_SUBST(LIBTOOL_DEPS)

AC_ARG_VAR([RONN], [path to the ronn text processor])
AC_PATH_PROG([RONN], [ronn], [#])

AC_ARG_VAR([SIXJACK], [path to 6jack])
AC_PATH_PROG([SIXJACK], [sixjack], [#])

AC_ARG_VAR([AR], [path to the ar utility])
AC_CHECK_TOOL([AR], [ar], [ar])

case $host_os in
  darwin*)
    case $build_os in
      darwin*)
        AC_ARG_VAR([DTRACE], [path to dtrace if you have it])
        AC_PATH_PROG([DTRACE], [dtrace])
      ;;
    esac
  ;;
esac
AS_IF([test -n "$DTRACE"],[
  PROBES_SOURCE="probes_dnscrypt_proxy.h"
],[
  DTRACE="#"
  PROBES_SOURCE="probes_no_dtrace.h"
])

AS_IF([test -d /usr/local/include], [
  CPPFLAGS="$CPPFLAGS -I/usr/local/include"
])

AS_IF([test -d /usr/local/lib], [
  LDFLAGS="$LDFLAGS -L/usr/local/lib"
])

dnl Checks for header files.

AC_SYS_LARGEFILE
AC_CHECK_HEADERS([sys/cdefs.h sys/feature_tests.h])
AC_CHECK_HEADERS([execinfo.h paths.h pwd.h uuid/uuid.h])
AC_CHECK_HEADERS([sandbox.h])

dnl Checks for typedefs, structures, and compiler characteristics.

AC_C_BIGENDIAN
AC_C_RESTRICT

AC_CHECK_TYPE([in_port_t], , [AC_DEFINE(in_port_t, uint16_t,
[in_port_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
])

AC_MSG_CHECKING([whether sin_len is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
]], [[
do {
 struct sockaddr_in a;
 (void) a.sin_len;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SIN_LEN,,[define if you have sin_len])
],[
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([whether __ss_family is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
]], [[
do {
 struct sockaddr_storage a;
 (void) a.__ss_family;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE___SS_FAMILY,,[define if you have __ss_family])
],[
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([whether ss_len is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
]], [[
do {
 struct sockaddr_storage a;
 (void) a.ss_len;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SS_LEN,,[define if you have ss_len])
],[
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([whether __ss_len is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
]], [[
do {
 struct sockaddr_storage a;
 (void) a.__ss_len;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE___SS_LEN,,[define if you have __ss_len])
],[
  AC_MSG_RESULT(no)
])

dnl Checks for library functions.

AC_SEARCH_LIBS(pow, [m])
AC_SEARCH_LIBS(dlopen, [dl])
AC_SEARCH_LIBS(clock_gettime, [rt],
  [AC_DEFINE(HAVE_CLOCK_GETTIME,,[define if you have clock_gettime()])])

AC_SEARCH_LIBS(backtrace, [execinfo],
  [AC_DEFINE(HAVE_BACKTRACE,,[define if you have backtrace()])])

AC_SEARCH_LIBS(gethostbyname, [resolv nsl])
AC_SEARCH_LIBS(recvfrom, [socket])
AC_SEARCH_LIBS(kvm_open, [kvm])

use_ldns=no
AC_CHECK_HEADER([ldns/ldns.h], [
  AC_CHECK_LIB(ldns, ldns_verify_trusted, [
    AC_DEFINE(USE_LDNS,,[define to use the ldns library])
    LDNS_LIBS=-lldns
    use_ldns=yes
  ])
], [ ],
[#include <stdlib.h>
 #include <stdint.h>])
AM_CONDITIONAL(USE_LDNS, test x$use_ldns = xyes)
AC_SUBST([LDNS_LIBS])

case $host_os in
  cygwin* | mingw* | pw32* | cegcc*)
    AC_CHECK_LIB([ws2_32], [_head_libws2_32_a])
    AC_CHECK_LIB([psapi], [_head_libpsapi_a])
    AC_CHECK_LIB([iphlpapi], [_head_libiphlpapi_a])
  ;;
esac

AC_CHECK_HEADER([CoreServices/CoreServices.h],
  [LIBS="$LIBS -framework CoreFoundation -framework CoreServices"])

AC_CHECK_FUNCS([getpwnam sandbox_init setrlimit putc_unlocked])

dnl Switches.

AC_ARG_ENABLE(pie,
[AS_HELP_STRING(--enable-pie,Produce position independent executables @<:@default=yes@:>@)],
 enable_pie=$enableval, enable_pie="maybe")

AC_ARG_ENABLE(ssp,
[AS_HELP_STRING(--disable-ssp,Don't compile with -fstack-protector)],
[AS_IF([test "x$enableval" = "xno"], [
    nxflags=""
    for flag in `echo $CFLAGS`; do
      case "$flag" in
       -fstack-protector*) ;;
        *) AS_VAR_APPEND([nxflags], [" $flag"]) ;;
      esac
    done
    CFLAGS="$nxflags"
  ])
])

plugins=disabled
AC_ARG_ENABLE(plugins,
[AS_HELP_STRING(--enable-plugins,Enable support for plugins - experimental)],
[CPPFLAGS="$CPPFLAGS -DPLUGINS=1"
 plugins=enabled])
AM_CONDITIONAL(PLUGINS, test x$plugins = xenabled)

relaxed_plugins_permissions=disabled
AC_ARG_ENABLE(relaxed-plugins-permissions,
[AS_HELP_STRING(--enable-relaxed-plugins-permissions,Allow loading plugins owned by other users)],
[CPPFLAGS="$CPPFLAGS -DRELAXED_PLUGINS_PERMISSIONS=1"
 relaxed_plugins_permissions=enabled])
AM_CONDITIONAL(RELAXED_PLUGINS_PERMISSIONS, test x$relaxed_plugins_permissions = xenabled)

plugins_root=disabled
AC_ARG_ENABLE(plugins-root,
[AS_HELP_STRING(--enable-plugins-root,Only load plugins sitting in the default plugins directory)],
[CPPFLAGS="$CPPFLAGS -DENABLE_PLUGINS_ROOT=1"
 plugins_root=enabled])
AM_CONDITIONAL(ENABLE_PLUGINS_ROOT, test x$plugins_root = xenabled)

AC_ARG_ENABLE(blocking-random,
[AS_HELP_STRING(--enable-blocking-random,Use /dev/random instead of /dev/urandom)],
[AC_DEFINE([USE_BLOCKING_RANDOM], [], [Use blocking random])])

AC_ARG_ENABLE(debug,
[AS_HELP_STRING(--enable-debug,For maintainers only - please do not use)],
[
  AS_IF([test "x$LX_CFLAGS" = "xNONE"], [
    nxflags=""
    for flag in `echo $CFLAGS`; do
      case "$flag" in
        -O*) ;;
        -g*) ;;
        *) AS_VAR_APPEND([nxflags], [" $flag"]) ;;
      esac
    done
    CFLAGS="$nxflags -O0 -g3"
  ])
  CPPFLAGS="$CPPFLAGS -DDEBUG=1"
])

AC_ARG_WITH(safecode,
[AS_HELP_STRING(--with-safecode,For maintainers only - please do not use)],
[AS_IF([test "x$withval" = "xyes"], [
    AC_ARG_VAR([SAFECODE_HOME], [set to the safecode base directory])
    : ${SAFECODE_HOME:=/opt/safecode}
    LDFLAGS="$LDFLAGS -L${SAFECODE_HOME}/lib"
    LIBS="$LIBS -lsc_dbg_rt -lpoolalloc_bitmap -lstdc++"
    CFLAGS="$CFLAGS -fmemsafety"
  ])
])

NACL_HOSTNAME="localhost"
NACL_PATH=libnacl/build/${NACL_HOSTNAME}

AC_SUBST([MAINT])
AC_SUBST([NACL_PATH])
AC_SUBST([PROBES_SOURCE])

dnl Libtool.

LT_INIT([dlopen])
LT_CONFIG_LTDL_DIR([libltdl])
LTDL_INIT

dnl Subconfig.

nx_ac_configure_args=""
for flag in $ac_configure_args; do
  case "$flag" in
    \'--build*) AS_VAR_APPEND([nx_ac_configure_args], [" $flag"]) ;;
    \'--host*)  AS_VAR_APPEND([nx_ac_configure_args], [" $flag"]) ;;
    *) ;;
  esac
done
ac_configure_args="$nx_ac_configure_args"

case $host_os in
  cygwin* | mingw* | pw32* | cegcc*) ;;
  *) ac_configure_args="$ac_configure_args --disable-thread-support" ;;
esac

ac_configure_args="$ac_configure_args --disable-dependency-tracking"
ac_configure_args="$ac_configure_args --disable-libevent-install"
ac_configure_args="$ac_configure_args --disable-openssl"
ac_configure_args="$ac_configure_args --disable-shared"
ac_configure_args="$ac_configure_args --enable-function-sections"
export CC
export CFLAGS
export CPP
export CPPFLAGS
export LDFLAGS
export LIBS

dnl Output.

AH_VERBATIM([NDEBUG], [/* Never ever ignore assertions */
#ifdef NDEBUG
#/**/undef/**/ NDEBUG
#endif])

AC_CONFIG_FILES([Makefile
                 dist-build/Makefile
                 man/Makefile
                 src/Makefile
                 src/hostip/Makefile
                 src/proxy/Makefile
                 src/ext/Makefile
                 src/include/Makefile
                 src/include/dnscrypt/version.h
                 src/libnacl/Makefile
                 src/libnacl/tests/Makefile
                 src/libnacl/okcompilers/c
                 src/libnacl/okcompilers/do
                 src/plugins/Makefile
                 src/plugins/example/Makefile
                 src/plugins/example-ldns-forward-after-nxdomain/Makefile
                 src/plugins/example-logging/Makefile
                 src/plugins/example-ldns-aaaa-blocking/Makefile
                 src/plugins/example-ldns-blocking/Makefile
                 src/plugins/example-ldns-opendns-deviceid/Makefile
                 test/Makefile])

AC_OUTPUT

chmod +x src/libnacl/do
chmod +x src/libnacl/okcompilers/do
