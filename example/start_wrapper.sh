#!/bin/sh

../dnscrypt-wrapper --resolver-address=114.114.114.114:53 --listen-address=0.0.0.0:8854 \
    --provider-name=2.dnscrypt-cert.yechengfu.com \
    --provider-cert-file=dnscrypt.cert \
    --crypt-secretkey-file=crypt_secret.key \
    -VV
