#! /bin/sh

export XCODEDIR="/Applications/Xcode.app/Contents/Developer"
export BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
export PATH="${BASEDIR}/usr/bin:$BASEDIR/usr/sbin:$PATH"
export SDK="${BASEDIR}/SDKs/iPhoneOS6.0.sdk"
export CFLAGS="-Oz -mthumb -arch armv7 -isysroot ${SDK}"
export LDFLAGS="-mthumb -arch armv7 -isysroot ${SDK}"

./configure --host=arm-apple-darwin10 && make -j3

echo 'Now, using codesign(1) to sign dnscrypt-proxy'
