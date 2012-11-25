#!/bin/sh
# Generate version automatically.

version=$(git describe --always --match "v[0-9]*" HEAD | sed -e 's/-/./g' | sed -e 's/^v//g')
version_file=VERSION

if test -f "$version_file"; then
    VC=$(sed -nr 's/^THE_VERSION = //p' $version_file)
else
    VC=unset
fi

if test "$VC" != "$version"; then
    echo "THE_VERSION = $version" > $version_file
fi
