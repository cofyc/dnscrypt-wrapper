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

for i in $(seq 1 32); do
    (
    server=127.0.0.1
    port=53
    # udp
    dig +short -p $port twitter.com @$server
    dig +short -p $port yechengfu.com @$server
    # tcp
    dig +short -p $port twitter.com @$server +tcp
    dig +short -p $port yechengfu.com @$server +tcp
    dig +short -p $port www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com @$server +tcp
    dig +short -p $port www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com @$server +tcp +dnssec +cdflag +edns=0

    server=127.0.0.1
    port=55
    # udp through dnscrypt-proxy
    dig +short -p $port twitter.com @$server
    dig +short -p $port yechengfu.com.com @$server
    # tcp through dnscrypt-proxy
    dig +short -p $port twitter.com @$server +tcp
    dig +short -p $port yechengfu.com.com @$server +tcp
    ) &
done

for i in $(seq 1 32); do
    (
    for ((a=1; a <= 2048; a++)); do dig -p 54 @127.0.0.1 yahoo.com +tcp +dnssec +edns=0 +cdflag; done
    ) &
done
