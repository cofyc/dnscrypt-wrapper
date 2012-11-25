#!@RCD_SCRIPTS_SHELL@
#
# PROVIDE: dnscrypt_proxy
# REQUIRE: DAEMON

. /etc/rc.subr

name="dnscrypt_proxy"
help_name="dnscrypt-proxy"
rcvar=$name
command="@PREFIX@/sbin/${help_name}"
pidfile="@VARBASE@/run/${help_name}.pid"
command_args="--daemonize --pidfile={$pidfile}"

load_rc_config $name
run_rc_command "$1"
