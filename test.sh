#!/bin/sh

for i in $(seq 1 32); do
    (
    server=127.0.0.1
    port=8854
    # udp
    dig +short -p $port twitter.com @$server
    dig +short -p $port yechengfu.com @$server
    # tcp
    dig +short -p $port twitter.com @$server +tcp
    dig +short -p $port yechengfu.com @$server +tcp
    dig +short -p $port www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com @$server +tcp
    dig +short -p $port www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com @$server +tcp +dnssec +cdflag +edns=0

    server=127.0.0.1
    port=8855
    # udp through dnscrypt-proxy
    dig +short -p $port twitter.com @$server
    dig +short -p $port yechengfu.com.com @$server
    # tcp through dnscrypt-proxy
    dig +short -p $port twitter.com @$server +tcp
    dig +short -p $port yechengfu.com.com @$server +tcp
    ) &
done
