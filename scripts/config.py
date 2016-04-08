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


import random,string
from iptools import IpRange
from iptools.ipv4 import validate_cidr
from os import chmod
from re import match
from shutil import copyfile
from subprocess import call
from urllib2 import urlopen

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
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    arr = [random.choice(chars) for i in range(len)]
    return ''.join(arr)

def check_duo():
    while True:
        duo_resp = prompt('Will you be using DUO for MFA: (y/N)', default='N')
        if (duo_resp == 'y' or duo_resp == 'Y'):
            host = prompt("DUO api host, e.g. api-XXXXXXXX.duosecurity.com")
            ikey = prompt("DUO integration key")
            skey = prompt("DUO secret key")
            return (host, ikey, skey)
        elif (duo_resp == 'n' or duo_resp == 'N'):
            host = ''
            ikey = ''
            skey = ''
            return (host, ikey, skey)
        else:
            print "Please enter 'y' or 'n'"

def gather_data():
    psk = prompt('Enter PSK', default=random_string(32))
    dns_prime = check_ip('Primary DNS', '8.8.8.8')
    dns_second = check_ip('Secondary DNS', '8.8.4.4')
    local_cidr = check_cidr('VPN IPv4 local CIDR', '10.11.12.0/24')
    local_ip = IpRange(local_cidr)[1]
    local_ip_range = IpRange(local_cidr)[10] + '-' + IpRange(local_cidr)[len(IpRange(local_cidr))-5]
    duo = check_duo()

    api_key = prompt('Foxpass API Key')
    radius_secret = random_string(16)

    public_ip = urlopen('http://169.254.169.254/latest/meta-data/public-ipv4').read()
    private_ip = urlopen('http://169.254.169.254/latest/meta-data/local-ipv4').read()

    holders = {'<PSK>': psk,
               '<DNS_PRIMARY>': dns_prime,
               '<DNS_SECONDARY>': dns_second,
               '<IP_RANGE>': local_ip_range,
               '<LOCAL_IP>': local_ip,
               '<LOCAL_SUBNET>': local_cidr,
               '<PUBLIC_IP>': public_ip,
               '<PRIVATE_IP>': private_ip,
               '<RADIUS_SECRET>': radius_secret,
               '<API_KEY>': api_key,
               '<DUO_API_HOST>': duo[0],
               '<DUO_IKEY>': duo[1],
               '<DUO_SKEY>': duo[2]
               }

    file_list = {'ipsec.secrets': '/etc/',
                 'iptables.rules': '/etc/',
                 'options.xl2tpd': '/etc/ppp/',
                 'xl2tpd.conf': '/etc/xl2tpd/',
                 'ipsec.conf':'/etc/',
                 'radius_agent_config.py': '/opt/bin/',
                 'servers': '/etc/radiusclient/'}

    return {'holders':holders, 'file_list':file_list}

def config_vpn(holders,file_list):
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
    chmod('/etc/ipsec.secrets',0600)
    call('/sbin/iptables-restore < /etc/iptables.rules', shell=True)
    for command in commands:
        call(['service',command,'stop'], shell=False)
        call(['service',command,'start'], shell=False)

if __name__ == '__main__':
    data = gather_data()
    config_vpn(data['holders'],data['file_list'])
