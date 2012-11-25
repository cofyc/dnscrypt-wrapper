#! /bin/sh

VERSION="1.1.0"
MAINTAINER="Frank Denis <dnscrypt@pureftpd.org>"
CATEGORY="net"
URL="http://dnscrypt.org"
VENDOR="OpenDNS"
DESCRIPTION="A tool for securing communications between a client and a DNS resolver
The DNSCrypt protocol is very similar to DNSCurve, but focuses on
securing communications between a client and its first-level resolver.
While not providing end-to-end security, it protects the local network
(which is often the weakest link in the chain) against
man-in-the-middle attacks. It also provides some confidentiality to
DNS queries.

The DNSCrypt daemon acts as a DNS proxy between a regular client, like
a DNS cache or an operating system stub resolver, and a DNSCrypt-aware
resolver, like OpenDNS."
TMPDIR=${TMPDIR:-/tmp}
BASE_DIR=$(mktemp -d "$TMPDIR"/dnscrypt.XXXXXX)
INSTALL_DIR="${BASE_DIR}/usr"
PKG_NAME="dnscrypt-proxy"
COPYRIGHT_FILE="COPYING"
DEBIAN_COPYRIGHT_FILE="${INSTALL_DIR}/share/doc/${PKG_NAME}/copyright"
DEBIAN_CHANGELOG_FILE="${INSTALL_DIR}/share/doc/${PKG_NAME}/changelog.gz"
LICENSE="bsd"

export TZ=""
export LC_ALL="C"
export LC_TIME="C"

./configure --prefix="$INSTALL_DIR" \
            --enable-plugins --enable-plugins-root && \
make -j4 install

mkdir -p -- $(dirname "$DEBIAN_COPYRIGHT_FILE") || exit 1
cp -- "$COPYRIGHT_FILE" "$DEBIAN_COPYRIGHT_FILE" || exit 1

echo "${PKG_NAME} (${VERSION}) unstable; urgency=medium
  * See ${URL}

 -- ${MAINTAINER}  $(date -R)" | gzip -9 > "$DEBIAN_CHANGELOG_FILE"

find "${INSTALL_DIR}/share/man" -type f -name "*.[0-9]" -exec gzip -9 {} \;

find "$BASE_DIR" -type d -exec chmod 755 {} \;

sudo chown -R 0:0 "$BASE_DIR" || exit 1

for t in deb rpm; do
  fpm -s dir -t "$t" -n "$PKG_NAME" -v "$VERSION" -C "$BASE_DIR" \
    -m "$MAINTAINER" --category "$CATEGORY" --url "$URL" --license "$LICENSE" \
    --vendor "$VENDOR" --description "$DESCRIPTION" \
    .
done
