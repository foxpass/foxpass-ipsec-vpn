#!/bin/bash

# quit if any command fails
set -e

mkdir /opt/src
cd /opt/src
SWAN_VER=3.18
SWAN_FILE="libreswan-${SWAN_VER}.tar.gz"
SWAN_URL="https://download.libreswan.org/$SWAN_FILE"
wget -t 3 -T 30 -nv -O "$SWAN_FILE" "$SWAN_URL"
/bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
tar xzf "$SWAN_FILE" && rm -f "$SWAN_FILE"
cd "libreswan-$SWAN_VER"

cat > Makefile.inc.local <<EOF
WERROR_CFLAGS =
EOF

make programs && make install

# delete libreswan source
cd /opt/src
rm -rf "libreswan-$SWAN_VER"

echo > /var/tmp/libreswan-nss-pwd
/usr/bin/certutil -N -f /var/tmp/libreswan-nss-pwd -d /etc/ipsec.d
/bin/rm -f /var/tmp/libreswan-nss-pwd

# install libreswan into systemd
systemctl enable ipsec.service
systemctl start ipsec.service

touch /etc/ipsec.conf
touch /etc/iptables.rules
touch /etc/ipsec.secrets
touch /etc/ppp/options.xl2tpd
touch /etc/xl2tpd/xl2tpd.conf
touch /etc/radiusclient/port-id-map
