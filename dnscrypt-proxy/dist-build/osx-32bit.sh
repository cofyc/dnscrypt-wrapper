#! /bin/sh

export CFLAGS="-mmacosx-version-min=10.6 -arch i386"
export LDFLAGS="-mmacosx-version-min=10.6 -arch i386"

export CPPFLAGS="$CPPFLAGS -I/opt/ldns/include"
export LDFLAGS="$LDFLAGS -L/opt/ldns/lib"

./configure --with-included-ltdl \
            --enable-plugins \
            --enable-plugins-root && \
make -j3
