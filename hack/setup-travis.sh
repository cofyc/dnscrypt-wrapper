#!/bin/bash

set -x

# Install unbound so we can test dnscrypt-wrapper.
apt-get install -y unbound

# Workaround where the container does not have ::1 but unbound default to
# binding to localhost (which is both 127.0.0.1 and ::1)
cat <<EOF > /etc/unbound/unbound.conf
server:
    interface: 127.0.0.1
remote-control:
    control-enable: no
EOF
service unbound restart
