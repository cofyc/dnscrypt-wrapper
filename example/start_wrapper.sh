#!/bin/bash

../dnscrypt-wrapper -d -a 0.0.0.0:8854 -r 8.8.8.8:53 \
    --crypt-secretkey-file=crypt_secret.key \
    --crypt-publickey-file=crypt_public.key --provider-cert-file=dnscrypt.cert \
    --provider-name=2.dnscrypt-cert.yechengfu.com -VV
