DNSCrypt
========

A tool for securing communications between a client and a DNS resolver.

Description
-----------

dnscrypt-proxy provides local service which can be used directly as
your local resolver or as a DNS forwarder, encrypting and
authenticating requests using the DNSCrypt protocol and passing them
to an upstream server, by default OpenDNS who run this on their
resolvers.

The DNSCrypt protocol uses high-speed high-security elliptic-curve
cryptography and is very similar to [DNSCurve](http://dnscurve.org/),
but focuses on securing communications between a client and its first-level
resolver.

While not providing end-to-end security, it protects the local
network, which is often the weakest point of the chain, against
man-in-the-middle attacks. It also provides some confidentiality to
DNS queries.

Installation
------------

The daemon is known to work on recent versions of OSX, OpenBSD,
Bitrig, NetBSD, Dragonfly BSD, FreeBSD, Linux, iOS (requires a
jailbroken device), Android (requires a rooted device), Solaris
(SmartOS) and Windows (requires MingW).

Download the [latest version](http://dnscrypt.org) and extract it:

    $ bunzip2 -cd dnscrypt-proxy-*.tar.bz2 | tar xvf -
    $ cd dnscrypt-proxy-*

Compile and install it using the standard procedure:

    $ ./configure && make -j2
    # make install

Replace `-j2` with whatever number of CPU cores you want to use for the
compilation process.

Running `make -j2 test` in the `src/libnacl` directory is also highly
recommended.

The proxy will be installed as `/usr/local/sbin/dnscrypt-proxy` by default.

Command-line switches are documented in the `dnscrypt-proxy(8)` man page.

*Note:* gcc 3.4.6 (and probably other similar versions) is known to
produce broken code on Mips targets with the -Os optimization level.
Use a different level (-O and -O2 are fine) or upgrade the compiler.
Thanks to Adrian Kotelba for reporting this.

GUIs for dnscrypt-proxy
-----------------------

If you need a simple graphical user interface in order to start/stop
the proxy and change your DNS settings, check out the following
projects:

- [DNSCrypt OSX Client](https://github.com/opendns/dnscrypt-osx-client):
A tool to easily use DNSCrypt with OpenDNS, configure plugins and
define resolvers for specific domains. It has been implemented as a
collection of shell scripts with a user interface in Objective C.

- [DNSCrypt WinClient](https://github.com/Noxwizard/dnscrypt-winclient):
Easily enable/disable DNSCrypt on multiple adapters. Supports
different ports and protocols, IPv6, parental controls and the proxy
can act as a gateway service. Windows only, written in .NET.

- [DNSCrypt Win Client](https://github.com/opendns/dnscrypt-win-client):
Official GUI for Windows, by OpenDNS. Also known as "OpenDNSCrypt".

- dnscrypt-proxy is also available on Cydia, and it can be easily
enabled using [GuizmoDNS](http://modmyi.com/cydia/com.guizmo.dns).

Usage
-----

Having a dedicated system user, with no privileges and with an empty
home directory, is highly recommended. For extra security, DNSCrypt
will chroot() to this user's home directory and drop root privileges
for this user's uid as soon as possible.

The easiest way to start the daemon is:

    # dnscrypt-proxy --daemonize

The proxy will accept incoming requests on 127.0.0.1, tag them with an
authentication code, forward them to OpenDNS resolvers, and validate
each answer before passing it to the client.

Given such a setup, in order to actually start using DNSCrypt, you
need to update your `/etc/resolv.conf` file and replace your current
set of resolvers with:

    nameserver 127.0.0.1

Other common command-line switches include:

* `--daemonize` in order to run the server as a background process.
* `--local-address=<ip>[:port]` in order to locally bind a different IP
address than 127.0.0.1
* `--logfile=<file>` in order to write log data to a dedicated file. By
  default, logs are sent to stdout if the server is running in foreground,
  and to syslog if it is running in background.
* `--max-active-requests=<count>` to set the maximum number of active
  requests. The default value is 250.
* `--pid-file=<file>` in order to store the PID number to a file.
* `--user=<user name>` in order to chroot()/drop privileges.

DNSCrypt comes pre-configured for OpenDNS, although the
`--resolver-address=<ip>[:port]`,
`--provider-name=<certificate provider FQDN>`
and `--provider-key=<provider public key>` can be specified in
order to change the default settings.

Installation as a service (Windows only)
----------------------------------------

The proxy can be installed as a Windows service.

Copy the `dnscrypt-proxy.exe` file to any location, then open a
terminal and type (eventually with the full path to `dnscrypt-proxy.exe`):

    dnscrypt-proxy.exe --install

It will install a new service named `dnscrypt-proxy`.

After being stopped, the service can be removed with:

    dnscrypt-proxy.exe --uninstall

Using DNSCrypt in combination with a DNS cache
----------------------------------------------

The DNSCrypt proxy is **not** a DNS cache. This means that incoming
queries will **not** be cached and every single query will require a
round-trip to the upstream resolver.

For optimal performance, the recommended way of running DNSCrypt is to
run it as a forwarder for a local DNS cache, like `unbound` or
`powerdns-recursor`.

Both can safely run on the same machine as long as they are listening
to different IP addresses (preferred) or different ports.

If your DNS cache is `unbound`, all you need is to edit the
`unbound.conf` file and add the following lines at the end of the `server`
section:

    do-not-query-localhost: no

    forward-zone:
      name: "."
      forward-addr: 127.0.0.1@40

The first line is not required if you are using different IP addresses
instead of different ports.

Then start `dnscrypt-proxy`, telling it to use a specific port (`40`, in
this example):

    # dnscrypt-proxy --local-address=127.0.0.1:40 --daemonize

IPv6 support
------------

IPv6 is fully supported. IPv6 addresses with a port number should be
specified as [ip]:port

    # dnscrypt-proxy --local-address='[::1]:40' --daemonize

Queries using nonstandard ports / over TCP
------------------------------------------

Some routers and firewalls can block outgoing DNS queries or
transparently redirect them to their own resolver. This especially
happens on public Wifi hotspots, such as coffee shops.

As a workaround, the port number can be changed using
the `--resolver-port=<port>` option. For example, OpenDNS servers
reply to queries sent to ports 53, 443 and 5353.

By default, dnscrypt-proxy sends outgoing queries to UDP port 443.

In addition, the DNSCrypt proxy can force outgoing queries to be
sent over TCP. For example, TCP port 443, which is commonly used for
communication over HTTPS, may not be filtered.

The `--tcp-only` command-line switch forces this behavior. When
an incoming query is received, the daemon immediately replies with a
"response truncated" message, forcing the client to retry over TCP.
The daemon then authenticates the query and forwards it over TCP
to the resolver.

`--tcp-only` is slower than UDP because multiple queries over a single
TCP connections aren't supported yet, and this workaround should
never be used except when bypassing a filter is actually required.

EDNS payload size
-----------------

DNS packets sent over UDP have been historically limited to 512 bytes,
which is usually fine for queries, but sometimes a bit short for
replies.

Most modern authoritative servers, resolvers and stub resolvers
support the Extension Mechanism for DNS (EDNS) that, among other
things, allows a client to specify how large a reply over UDP can be.

Unfortunately, this feature is disabled by default on a lot of
operating systems. It has to be explicitly enabled, for example by
adding `options edns0` to the `/etc/resolv.conf` file on most
Unix-like operating systems.

`dnscrypt-proxy` can transparently rewrite outgoing packets before
authenticating them, in order to add the EDNS0 mechanism. By
default, a conservative payload size of 1252 bytes is advertised.

This size can be made larger by starting the proxy with the
`--edns-payload-size=<bytes>` command-line switch. Values up to 4096
are usually safe.

A value below or equal to 512 will disable this mechanism, unless a
client sends a packet with an OPT section providing a payload size.

The `hostip` utility
--------------------

The DNSCrypt proxy ships with a simple tool named `hostip` that
resolves a name to IPv4 or IPv6 addresses.

This tool can be useful for starting some services before
`dnscrypt-proxy`.

Queries made by `hostip` are not authenticated.
