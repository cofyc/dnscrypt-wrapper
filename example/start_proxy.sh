#!/bin/sh

dnscrypt-proxy -a 127.0.0.1:8855 -r 127.0.0.1:8854 \
    --provider-name=2.dnscrypt-cert.example.com \
    --provider-key=3686:91DF:DC22:8DBB:67BF:9EF6:5471:C831:B468:E0F8:18D9:6CB1:254E:3BE7:7A88:AB24
