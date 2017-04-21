#
# Process this file with autoconf to produce a configure script.
#
# Run ./configure with your options to generate config.mak.autogen file which
# is used by Makefile.
#

## Definitions of private macros.

# CONF_SUBST_INIT
# -------------------
# Prepare shell variables and autoconf machine required by later calls
# to CONF_SUBST.
AC_DEFUN([CONF_SUBST_INIT],
    [config_appended_defs=; newline='
'
    AC_CONFIG_COMMANDS([$config_file],
                       [echo "$config_appended_defs" >> "$config_file"],
                       [config_file=$config_file
                        config_appended_defs="$config_appended_defs"])]
)

# CONF_SUBST(VAL, VAR)
# ------------------------
# Cause the line "VAR=VAL" to be eventually appended to ${config_file}.
AC_DEFUN([CONF_SUBST], [AC_REQUIRE([CONF_SUBST_INIT])
config_appended_defs="$config_appended_defs${newline}dnl
$1=m4_if([$#],[1],[${$1}],[$2])"]
)

## Configure body starts here.

AC_PREREQ([2.59])
AC_INIT

config_file=config.mak.autogen
config_in=config.mak.in

# AUTOCONFIGURED
CONF_SUBST([AUTOCONFIGURED], [YesPlease])

# Checks for programs
AC_PROG_CC
AC_CHECK_TOOLS(AR, [gar ar], :)
AC_CHECK_PROGS(TAR, [gtar tar])

# libevent
AC_ARG_WITH(event,
    [AS_HELP_STRING([--with-event=DIR], [where to find the event library])],
    [if test -d "$withval"; then
        LDFLAGS="$LDFLAGS -L$withval/lib"
        CFLAGS="$CFLAGS -I$withval/include"
    fi],
    withval=yes # default
)
if test "$withval" != no; then
    AC_CHECK_LIB(event,event_base_new,
        [LIBS="-levent $LIBS"],
        [AC_MSG_ERROR([libevent2 is required - see http://libevent.org/])]
    )   
    AC_CHECK_HEADERS(event2/event.h,
        [LIBS="-levent $LIBS"],
        [AC_MSG_ERROR([libevent2 is required - see http://libevent.org/])]
    )
fi

# libsodium
AC_ARG_WITH(sodium,
    [AS_HELP_STRING([--with-sodium=DIR], [where to find the sodium library])],
    [if test -d "$withval"; then
        LDFLAGS="$LDFLAGS -L$withval/lib"
        CFLAGS="$CFLAGS -I$withval/include"
    fi],
    withval=yes # default
)
if test "$withval" != no; then
    AC_CHECK_LIB(sodium,sodium_init,
        [LIBS="-lsodium $LIBS"],
        [AC_MSG_ERROR([sodium is required - see https://github.com/jedisct1/libsodium])]
    )   
fi

AC_CHECK_FUNCS(crypto_box_curve25519xchacha20poly1305_open_easy,
    [CFLAGS="$CFLAGS -DHAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_OPEN_EASY"],
    [AC_MSG_WARN([was libsodium compiled with --enable-minimal])]
)

# Output files
AC_CONFIG_FILES(["${config_file}":"${config_in}"])
AC_OUTPUT

# Show summary.
AC_MSG_RESULT([
Configuration summary:

    Support for event library: $ac_cv_lib_event_event_base_new
    Support for sodium library: $ac_cv_lib_sodium_sodium_init
    Support for xchacha20: $ac_cv_func_crypto_box_curve25519xchacha20poly1305_open_easy
])
