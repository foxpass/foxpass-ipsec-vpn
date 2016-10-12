#!/usr/bin/python

# Copyright (c) 2015-present, Foxpass, Inc.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import random
from iptools import IpRange
from iptools.ipv4 import validate_cidr
from os import chown, chmod, urandom
from re import match
from shutil import copyfile
import socket
import string
from subprocess import call
from urllib2 import urlopen, Request

from iptools import IpRange
from iptools.ipv4 import validate_cidr
from python_hosts import Hosts, HostsEntry

METADATA_BASE_URL = "http://169.254.169.254/"

def check_ip(target, default=None):
    while True:
        try:
            ip = prompt("Enter %s: " % target, default)
            str(IpRange(ip))
        except TypeError:
            print "%s is not a valid IP." % ip
        else:
            return ip

def check_cidr(target, default=None):
    while True:
        try:
            cidr = prompt("Enter %s: " % target, default)
            if validate_cidr(cidr):
                pass
            else:
                print "%s is not a valid CIDR." % cidr
            if int(cidr.split('/')[1]) > 27:
                print "%s is too small, use a larger network size." % cidr
            else:
                return cidr
        except:
            pass

def prompt(message, default=None):
    if default:
        return raw_input( '%s [%s]: ' % (message, default) ) or default
    else:
        return raw_input( '%s: ' % (message) )

def random_string(len):
    system_random = random.SystemRandom()
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    arr = [system_random.choice(chars) for i in range(len)]
    return ''.join(arr)

def get_duo_data():
    while True:
        duo_resp = prompt('Will you be using DUO for MFA: (y/N)', default='N')
        if (duo_resp == 'y' or duo_resp == 'Y'):
            host = prompt("DUO api host, e.g. api-XXXXXXXX.duosecurity.com")
            ikey = prompt("DUO integration key")
            skey = prompt("DUO secret key")
            return {'host': host, 'ikey': ikey, 'skey': skey}
        elif (duo_resp == 'n' or duo_resp == 'N'):
            return None
        else:
            print "Please enter 'y' or 'n'"

def is_gce():
    try:
        response = urlopen(METADATA_BASE_URL)
        try:
            return response.info().get("Metadata-Flavor") == "Google"
        finally:
            response.close()
    except Exception:
        return False

def gather_data():
    data = {}

    data['psk'] = prompt('Enter PSK', default=random_string(32))
    data['dns_prime'] = check_ip('Primary DNS', '8.8.8.8')
    data['dns_second'] = check_ip('Secondary DNS', '8.8.4.4')
    data['local_cidr'] = check_cidr('VPN IPv4 local CIDR', '10.11.12.0/24')
    data['local_ip'] = IpRange(data['local_cidr'])[1]
    data['local_ip_range'] = IpRange(data['local_cidr'])[10] + '-' + IpRange(data['local_cidr'])[len(IpRange(data['local_cidr']))-5]
    data['duo_config'] = get_duo_data()

    data['api_key'] = prompt('Foxpass API Key')
    data['radius_secret'] = random_string(16)

    data['is_gce'] = is_gce()

    if data['is_gce']:
        headers = {'Metadata-Flavor': 'Google'}
        request = Request(METADATA_BASE_URL + 'computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip', headers=headers)
        data['public_ip'] = urlopen(request).read()
        request = Request(METADATA_BASE_URL + 'computeMetadata/v1/instance/network-interfaces/0/ip', headers=headers)
        data['private_ip'] = urlopen(request).read()
    else:
        data['public_ip'] = urlopen(METADATA_BASE_URL + 'latest/meta-data/public-ipv4').read()
        data['private_ip'] = urlopen(METADATA_BASE_URL + 'latest/meta-data/local-ipv4').read()

    return data

def modify_etc_hosts(data):
    private_ip = data['private_ip']
    hostname = socket.gethostname()

    hosts = Hosts()
    new_entry = HostsEntry(entry_type='ipv4',
                           address=private_ip,
                           names=[hostname])
    hosts.add([new_entry])
    hosts.write()

def config_vpn(data):
    holders = {'<PSK>': data['psk'],
               '<DNS_PRIMARY>': data['dns_prime'],
               '<DNS_SECONDARY>': data['dns_second'],
               '<IP_RANGE>': data['local_ip_range'],
               '<LOCAL_IP>': data['local_ip'],
               '<LOCAL_SUBNET>': data['local_cidr'],
               '<PUBLIC_IP>': data['public_ip'],
               '<PRIVATE_IP>': data['private_ip'],
               '<RADIUS_SECRET>': data['radius_secret'],
               '<API_KEY>': data['api_key'],
               '<DUO_API_HOST>': data['duo_config'].get('host', '') if data['duo_config'] else '',
               '<DUO_IKEY>': data['duo_config'].get('ikey', '') if data['duo_config'] else '',
               '<DUO_SKEY>': data['duo_config'].get('skey', '') if data['duo_config'] else ''
               }

    file_list = {'ipsec.secrets': '/etc/',
                 'iptables.rules': '/etc/',
                 'options.xl2tpd': '/etc/ppp/',
                 'xl2tpd.conf': '/etc/xl2tpd/',
                 'ipsec.conf':'/etc/',
                 'foxpass-radius-agent.conf': '/etc/',
                 'servers': '/etc/radiusclient/'}


    templates = '/opt/templates'
    files = {}
    for file in file_list.iterkeys():
        path = '%s/%s' % (templates,file)
        files[file] = open(path,'r').read()
    for file,source in files.iteritems():
        dest = open(file_list[file]+file,'w')
        for orig,repl in holders.iteritems():
            source = source.replace(orig,repl)
        dest.write(source)
        dest.close()
    commands = ['xl2tpd','ipsec','fail2ban', 'foxpass-radius-agent']
    call(['/sbin/sysctl','-p'])
    # set /etc/ipsec.secrets to be owned and only accessible by root
    # chmod 0600 is r/w owner
    # chown 0 is set user to root
    chmod('/etc/ipsec.secrets',0600)
    chown('/etc/ipsec.secrets',0)
    call('/sbin/iptables-restore < /etc/iptables.rules', shell=True)
    for command in commands:
        call(['service',command,'stop'], shell=False)
        call(['service',command,'start'], shell=False)

if __name__ == '__main__':
    data = gather_data()
    modify_etc_hosts(data)
    config_vpn(data)
