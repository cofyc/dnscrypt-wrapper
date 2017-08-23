#!/bin/sh

../dnscrypt-wrapper --resolver-address=8.8.8.8:53 --listen-address=0.0.0.0:8854 \
    --provider-name=2.dnscrypt-cert.example.com \
    --provider-cert-file=1.cert \
    --crypt-secretkey-file=1.key \
    -VV
