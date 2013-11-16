Name
====

dnscrypt-wrapper - A server-side dnscrypt proxy.

(c) 2012-2013 Yecheng Fu <cofyc.jackson at gmail dot com>

[![Build Status](https://travis-ci.org/Cofyc/dnscrypt-wrapper.png?branch=master)](https://travis-ci.org/Cofyc/dnscrypt-wrapper)

[中文](README.cn.md)

Description
===========

This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to
add dnscrypt support to any name resolver.

This software is modified from
[dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy).

Installation
============

Install [libsodium](https://github.com/jedisct1/libsodium) and libevent2 first.

On Linux, don't forget to run `ldconfig` if you installed it from
source.

    $ git clone --recursive git://github.com/Cofyc/dnscrypt-wrapper.git
    $ make
    $ make install

Gentoo ebuild
-------------

See https://github.com/Cofyc/portage-overlay/tree/master/net-misc/dnscrypt-wrapper.
    
Usage
=====

First, generate provider keypair:

    # stored in public.key/secret.key in current directory
    $ ./dnscrypt-wrapper --gen-provider-keypair

Second, generate crypt keypair:

    # stored in crypt_public.key/crypt_secret.key in current directory
    $ ./dnscrypt-wrapper --gen-crypt-keypair

Third, generate pre-signed certificate (use pre-generated key pairs):

    # stored in dnscrypt.cert in current directory
    $ ./dnscrypt-wrapper --crypt-secretkey-file misc/crypt_secret.key --crypt-publickey-file=misc/crypt_public.key --provider-publickey-file=misc/public.key --provider-secretkey-file=misc/secret.key --gen-cert-file

Run the program with pre-signed certificate:

    $ ./dnscrypt-wrapper  -r 8.8.8.8:53 -a 0.0.0.0:54  --crypt-secretkey-file=misc/crypt_secret.key --crypt-publickey-file=misc/crypt_public.key --provider-cert-file=misc/dnscrypt.cert --provider-name=2.dnscrypt-cert.yechengfu.com -VV

If you can store genearted pre-signed certificate (binary string) in TXT record for your provider name, for example: 2.dnscrypt-cert.yourdomain.com. Then you can omit `--provider-cert-file` option. Name server will serve this binary certificate data for you.

P.S. We still provide `--provider-cert-file` option, because it's not convenient to store such long binary data in dns TXT record sometimes. But it's easy to configure it in your own dns servers (such as tinydns, etc). `--gen-cert-file` will generate example record in stdout.

Run dnscrypt-proxy to test againt it:

    # --provider-key is public key fingerprint in first step.
    $ ./dnscrypt-proxy -a 127.0.0.1:55 --provider-name=2.dnscrypt-cert.yechengfu.com -r 127.0.0.1:54 --provider-key=4298:5F65:C295:DFAE:2BFB:20AD:5C47:F565:78EB:2404:EF83:198C:85DB:68F1:3E33:E952
    $ dig -p 55 google.com @127.0.0.1

Optional, add "-d/--daemonize" flag to run as daemon.

Run "./dnscrypt-wrapper -h" to view command line options.

See also
========
    
- http://dnscrypt.org/
- http://www.opendns.com/technology/dnscrypt/
