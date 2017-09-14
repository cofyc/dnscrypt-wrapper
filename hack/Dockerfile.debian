FROM ubuntu:16.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && sed -i /security.ubuntu.com/d /etc/apt/sources.list \
    && apt-get update -y \
    && apt-get -yy -q install --no-install-recommends --no-install-suggests --fix-missing \
        dpkg-dev \
        build-essential \
        debhelper \
        dh-systemd \
        dh-autoreconf \
        fakeroot \
        devscripts

ADD hack/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
