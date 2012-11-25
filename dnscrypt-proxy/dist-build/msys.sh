#! /bin/sh

export CFLAGS="-Os -march=pentium2 -mtune=nocona"

./configure --disable-ssp --enable-plugins --with-included-ltdl && \
  make -j3 install-strip

upx --best --ultra-brute /usr/local/sbin/dnscrypt-proxy.exe &
upx --best --ultra-brute /usr/local/bin/hostip.exe

wait
