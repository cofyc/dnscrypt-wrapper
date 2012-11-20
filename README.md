NAME
====

dnscrypt-wrapper - A server-side dnscrypt proxy.

DESCRIPTION
===========

This is dnscrypt wrapper, a server-side dnscrypt proxy that helps to and dnscrypt support to any dns server.

This software is modified from
[dnscrypt-proxy](https://github.com/opendns/dnscrypt-proxy).

Only udp protocol is supported now, tcp is work in progress.

INSTALLATION
============

    $ make
    $ make install
    
Usage
=====

First, generate provider keypair:

    # stored in public.key/secret.key in current directory
    $ ./dnscrypt-wrapper --gen-provider-keypair

Second, generate crypt keypair:

    # stored in crypt_public.key/crypt_secret.key in current directory
    $ ./dnscrypt-wrapper --gen-crypt-keypair

Run the program, for example (use keypairs in misc/ directory):

    $ ./dnscrypt-wrapper -r 8.8.8.8:53 -a 0.0.0.0:54 --provider-publickey-file=misc/public.key --provider-secretkey-file=misc/secret.key --crypt-secretkey-file=misc/crypt_secret.key --crypt-publickey-file=misc/crypt_public.key --provider-name=2.dnscrypt-cert.yechengfu.com -VV

Optional, add "-d/--daemonize" flag to run as daemon.

Run "./dnscrypt-wrapper -h" to view help.

See also
========
    
- http://dnscrypt.org/
- http://www.opendns.com/technology/dnscrypt/
