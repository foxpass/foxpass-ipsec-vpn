#!/bin/bash

apt-get -y update
apt-get -y install wget dnsutils libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison gcc make libunbound-dev libnss3-tools libevent-dev libradius1 xl2tpd fail2ban python-pyrad python-pip
apt-get -y --no-install-recommends install xmlto
pip install duo_client
pip install iptools

mkdir /opt/src
cd /opt/src
SWAN_VER=3.17
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

touch /etc/ipsec.conf
touch /etc/iptables.rules
touch /etc/ipsec.secrets
touch /etc/ppp/options.xl2tpd
touch /etc/xl2tpd/xl2tpd.conf
touch /etc/radiusclient/port-id-map
