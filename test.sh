#!/bin/bash

# directly to dnscrypt-wrapper
dig +short -p 54 twitter.com @127.0.0.1
dig +short -p 54 twitter.com @127.0.0.1 +tcp

# through dnscrypt-proxy
dig +short -p 55 twitter.com @127.0.0.1
dig +short -p 55 twitter.com @127.0.0.1 +tcp
