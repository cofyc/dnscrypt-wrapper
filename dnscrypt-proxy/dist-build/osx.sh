#! /bin/sh

export CFLAGS="-mmacosx-version-min=10.6"
export LDFLAGS="-mmacosx-version-min=10.6"

./configure --with-included-ltdl \
            --enable-plugins \
            --enable-plugins-root && \
make -j3
