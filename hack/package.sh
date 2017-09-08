#!/bin/bash
#
# A script used to package dnscrypt-wrapper. It depends on docker.
#

ROOT=$(unset CDPATH && cd $(dirname "${BASH_SOURCE[0]}")/.. && pwd)
cd $ROOT

docker build -t dnscrypt-wrapper-packager -f hack/Dockerfile.debian .
docker run -v $ROOT:/src/dnscrypt-wrapper --rm -it dnscrypt-wrapper-packager
