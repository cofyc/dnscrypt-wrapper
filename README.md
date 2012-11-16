NAME
====

dnscrypt-wrapper - A server-side dnscrypt proxy.

DESCRIPTION
===========

This is dnscrypt wrapper, which enables dnscrypt support for any dns server.

INSTALLATION
============

    $ make
    $ make install
    
Usage
=====

	$ dnscrypt-wrapper --daemonize --listen-address=<local ip:port> --resolver-address=<dns server ip:port>

See also
========
    
- http://dnscrypt.org/
- http://www.opendns.com/technology/dnscrypt/
