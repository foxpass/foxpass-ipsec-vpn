FROM ubuntu:20.04

#RUN mkdir /app
#WORKDIR /app

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libnss3-dev libnspr4-dev pkg-config libpam-dev \
 libcap-ng-dev libcap-ng-utils libselinux-dev \
 libcurl3-nss-dev flex bison gcc make libldns-dev \
 libunbound-dev libnss3-tools libevent-dev \
 libsystemd-dev git devscripts build-essential fakeroot libsystemd-dev python3-pip wget xl2tpd xmlto
RUN mkdir /tmp/foxpass-vpn

COPY scripts /tmp/foxpass-vpn/scripts
COPY templates /tmp/foxpass-vpn/templates
COPY static /tmp/foxpass-vpn/static
COPY foxpass-radius-agent /tmp/foxpass-vpn/foxpass-radius-agent
COPY requirements.txt /tmp/foxpass-vpn/requirements.txt

RUN pip3 install -r /tmp/foxpass-vpn/requirements.txt
RUN pip3 install -r /tmp/foxpass-vpn/foxpass-radius-agent/requirements.txt

RUN /tmp/foxpass-vpn/scripts/setup.sh 

RUN mkdir /opt/bin

RUN mv /tmp/foxpass-vpn/templates /opt/
RUN mv /tmp/foxpass-vpn/scripts/config.py /opt/bin/config.py
RUN mv /tmp/foxpass-vpn/scripts/sshd_config /etc/ssh/sshd_config
RUN mv /tmp/foxpass-vpn/scripts/sysctl.conf /etc/sysctl.conf
# docker does not have this directory
# RUN mv /tmp/foxpass-vpn/scripts/iptablesload /etc/network/if-pre-up.d/iptablesload
RUN mv /tmp/foxpass-vpn/static/radiusclient /etc
RUN mv /tmp/foxpass-vpn/foxpass-radius-agent/foxpass-radius-agent.py /usr/local/bin
RUN mv /tmp/foxpass-vpn/foxpass-radius-agent/systemd/foxpass-radius-agent.service /lib/systemd/system/
RUN systemctl enable foxpass-radius-agent.service
RUN chmod 744 /opt/bin/config.py"

CMD python3 /opt/bin/setup.py
