#!/bin/bash

set -e

apt-get install -y libsodium-dev libevent-dev

cd /src/dnscrypt-wrapper
debuild -us -uc
