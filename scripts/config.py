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

# system libs
import json
import random
import socket
import string
import sys
from os import chown, chmod, geteuid, urandom
from re import match
from shutil import copyfile
from subprocess import call
from urllib2 import urlopen, Request
from urlparse import urlparse

# third party libs
import ifaddr
from iptools import IpRange
from iptools.ipv4 import validate_cidr
from python_hosts import Hosts, HostsEntry

# require running as root
if geteuid() != 0:
    exit("Not running as root.\nconfig.py requires root privileges, please run again using sudo")

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
        except Exception:
            pass


def prompt(message, default=None):
    if default:
        return raw_input('%s [%s]: ' % (message, default)) or default
    else:
        return raw_input('%s: ' % (message))


def random_string(len):
    system_random = random.SystemRandom()
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    arr = [system_random.choice(chars) for i in range(len)]
    return ''.join(arr)


def get_mfa_type():
    while True:
        mfa_resp = prompt('Will you be using MFA: (y/N)', default='N')
        if (mfa_resp == 'y' or mfa_resp == 'Y'):
            while True:
                mfa_type = prompt('What MFA provider: (duo/okta/Cancel)', default='Cancel')
                mfa_type = mfa_type.lower()
                if (mfa_type == 'duo' or mfa_type == 'okta'):
                    return mfa_type
                elif (mfa_type == 'cancel'):
                    return ''
                else:
                    print "Please enter 'duo', 'okta', or 'Cancel'"
        elif (mfa_resp == 'n' or mfa_resp == 'N'):
            return ''
        else:
            print "Please enter 'y' or 'n'"


def get_duo_data():
    host = prompt("DUO api host, e.g. api-XXXXXXXX.duosecurity.com")
    ikey = prompt("DUO integration key")
    skey = prompt("DUO secret key")
    return {'api_host': host, 'ikey': ikey, 'skey': skey}


def get_okta_data():
    hostname = prompt("OKTA api hostname, e.g. XXXXXXXX.okta.com")
    apikey = prompt("OKTA api key")
    return {'hostname': hostname, 'apikey': apikey}


def is_gce():
    try:
        response = urlopen(METADATA_BASE_URL)
        try:
            return response.info().get("Metadata-Flavor") == "Google"
        finally:
            response.close()
    except Exception:
        return False


def gather_user_data_prompt():
    data = {}

    data['psk'] = prompt('Enter PSK', default=random_string(32))
    data['dns_primary'] = check_ip('Primary DNS', '1.1.1.1')
    data['dns_secondary'] = check_ip('Secondary DNS', '1.0.0.1')
    data['local_cidr'] = check_cidr('VPN IPv4 local CIDR', '10.11.12.0/24')

    mfa_type = get_mfa_type()
    data['mfa_type'] = mfa_type
    if mfa_type == 'duo':
        data['duo_config'] = get_duo_data()
    elif mfa_type == 'okta':
        data['okta_config'] = get_okta_data()

    data['foxpass_api_key'] = prompt('Foxpass API Key')

    require_groups = prompt('Limit to groups (comma-separated)')

    if require_groups:
        data['require_groups'] = require_groups.split(',')

    return data


def gather_user_data_s3(s3_url):
    import boto
    from boto.s3.connection import S3Connection

    parts = urlparse(s3_url)

    if parts.scheme != 's3':
        raise Exception("Must use s3 url scheme")

    bucket_name = parts.netloc
    path = parts.path

    conn = boto.connect_s3()
    bucket = conn.get_bucket(bucket_name)
    if not bucket:
        raise Exception("Can't find bucket '%s'" % bucket_name)

    key = bucket.get_key(path)
    if not key:
        raise Exception("Can't find file '%s'" % path)

    data = key.get_contents_as_string()
    return json.loads(data)


def gather_user_data_file(filename):
    return json.load(file(filename))


def get_machine_data():
    data = {}

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

    data['interface'] = get_adapter(data['private_ip'])

    return data


def get_adapter(private_ip):
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        for ip in adapter.ips:
            if ip.ip == private_ip:
                return adapter.nice_name


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
    mfa_type = ''

    duo_api_host = ''
    duo_ikey = ''
    duo_skey = ''

    okta_hostname = ''
    okta_apikey = ''

    if 'mfa_type' in data:
        mfa_type = data['mfa_type']

    if 'duo_config' in data:
        duo_api_host = data['duo_config'].get('api_host')
        duo_ikey = data['duo_config'].get('ikey')
        duo_skey = data['duo_config'].get('skey')

    if 'okta_config' in data:
        okta_hostname = data['okta_config'].get('hostname')
        okta_apikey = data['okta_config'].get('apikey')

    local_ip_range = IpRange(data['local_cidr'])[10] + '-' + IpRange(data['local_cidr'])[len(IpRange(data['local_cidr'])) - 5]
    local_ip = IpRange(data['local_cidr'])[1]
    holders = {'<PSK>': data['psk'],
               '<DNS_PRIMARY>': data['dns_primary'],
               '<DNS_SECONDARY>': data['dns_secondary'],
               '<IP_RANGE>': local_ip_range,
               '<LOCAL_IP>': local_ip,
               '<LOCAL_SUBNET>': data['local_cidr'],
               '<PUBLIC_IP>': data['public_ip'],
               '<PRIVATE_IP>': data['private_ip'],
               '<INTERFACE>': data['interface'],
               '<RADIUS_SECRET>': data['radius_secret'],
               '<API_KEY>': data['foxpass_api_key'],
               '<REQUIRE_GROUPS>': ','.join(data['require_groups']) if 'require_groups' in data else '',
               '<MFA_TYPE>': mfa_type,
               '<DUO_API_HOST>': duo_api_host,
               '<DUO_IKEY>': duo_ikey,
               '<DUO_SKEY>': duo_skey,
               '<OKTA_HOSTNAME>': okta_hostname,
               '<OKTA_APIKEY>': okta_apikey
               }

    file_list = {'ipsec.secrets': '/etc/',
                 'iptables.rules': '/etc/',
                 'options.xl2tpd': '/etc/ppp/',
                 'xl2tpd.conf': '/etc/xl2tpd/',
                 'ipsec.conf': '/etc/',
                 'foxpass-radius-agent.conf': '/etc/',
                 'servers': '/etc/radiusclient/'}

    templates = '/opt/templates'
    files = {}
    for file in file_list.iterkeys():
        path = '%s/%s' % (templates, file)
        files[file] = open(path, 'r').read()
    for file, source in files.iteritems():
        dest = open(file_list[file] + file, 'w')
        for orig, repl in holders.iteritems():
            source = source.replace(orig, repl)
        dest.write(source)
        dest.close()
    commands = ['xl2tpd', 'ipsec', 'fail2ban', 'foxpass-radius-agent']
    call(['/sbin/sysctl', '-p'])
    # set /etc/ipsec.secrets to be owned and only accessible by root
    # chmod 0600 is r/w owner
    # chown 0 is set user to root
    chmod('/etc/ipsec.secrets', 0600)
    chown('/etc/ipsec.secrets', 0, 0)
    call('/sbin/iptables-restore < /etc/iptables.rules', shell=True)
    for command in commands:
        call(['service', command, 'stop'], shell=False)
        call(['service', command, 'start'], shell=False)


def main():
    # only allowed argument is pointer to json file on-disk or in s3
    if len(sys.argv) > 1:
        if sys.argv[1].startswith('s3:'):
            data = gather_user_data_s3(sys.argv[1])
        else:
            data = gather_user_data_file(sys.argv[1])
    else:
        data = gather_user_data_prompt()

    # update with machine data
    machine_data = get_machine_data()
    data.update(machine_data)

    # ppp won't work if the hostname can't resolve, so make sure it's in /etc/hosts
    modify_etc_hosts(data)
    config_vpn(data)


if __name__ == '__main__':
    main()
