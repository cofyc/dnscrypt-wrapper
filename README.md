NAME
====

dnscrypt-wrapper - A server-side dnscrypt proxy.

DESCRIPTION
===========

This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to add dnscrypt support to any dns server

This software is modified from
[dnscrypt-proxy](https://github.com/opendns/dnscrypt-proxy).

Only udp protocol is supported now, tcp is work in progress.

INSTALLATION
============

    $ git clone git://github.com/Cofyc/dnscrypt-wrapper.git
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

Run dnscrypt-proxy to test againt it:

    $ ./dnscrypt-proxy -a 127.0.0.1:55 --pvider-name=2.dnscrypt-cert.yechengfu.com -r 127.0.0.1:54 --provider-key=4298:5F65:C295:DFAE:2BFB:20AD:5C47:F565:78EB:2404:EF83:198C:85DB:68F1:3E33:E952
    $ dig -p 55 google.com @127.0.0.1

Optional, add "-d/--daemonize" flag to run as daemon.

Run "./dnscrypt-wrapper -h" to view help.

See also
========
    
- http://dnscrypt.org/
- http://www.opendns.com/technology/dnscrypt/
