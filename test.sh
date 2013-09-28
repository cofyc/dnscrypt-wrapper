#!/bin/bash
#
# dnscrypt-wrapper: 
#
#   sudo ./dnscrypt-wrapper -r 8.8.8.8:53 --crypt-secretkey-file=./misc/crypt_secret.key --crypt-publickey-file=./misc/crypt_public.key  --provider-name=2.dnscrypt-cert.yechengfu.com --provider-cert-file=./misc/dnscrypt.cert -VV -a 0.0.0.0:54
#
# dnscrypt-proxy:
#
#   sudo ./dnscrypt-proxy -a 127.0.0.1:55 --provider-name=2.dnscrypt-cert.yechengfu.com -r 127.0.0.1:54 --provider-key=4298:5F65:C295:DFAE:2BFB:20AD:5C47:F565:78EB:2404:EF83:198C:85DB:68F1:3E33:E952 -m 100
#

# udp
dig +short -p 54 twitter.com @127.0.0.1
dig +short -p 54 yechengfu.com @127.0.0.1
# udp through dnscrypt-proxy
dig +short -p 55 twitter.com @127.0.0.1
dig +short -p 55 yechengfu.com.com @127.0.0.1

# tcp
dig +short -p 54 twitter.com @127.0.0.1 +tcp
dig +short -p 54 yechengfu.com @127.0.0.1 +tcp
dig +short -p 54 www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com @127.0.0.1 +tcp
# tcp through dnscrypt-proxy
dig +short -p 55 twitter.com @127.0.0.1 +tcp
dig +short -p 55 yechengfu.com.com @127.0.0.1 +tcp
