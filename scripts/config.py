#!/usr/bin/python3

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
import os
import random
import socket
import string
import sys
from os import chmod, chown, geteuid, urandom
from re import match
from shutil import copyfile
from subprocess import call
from urllib.parse import urlparse

# third party libs
import ifaddr
import requests
from iptools import IpRange
from iptools.ipv4 import validate_cidr
from jinja2 import Environment, FileSystemLoader
from python_hosts import Hosts, HostsEntry

# require running as root
if geteuid() != 0:
    exit(
        "Not running as root.\nconfig.py requires root privileges, please run again using sudo"
    )

METADATA_BASE_URL = "http://169.254.169.254/"


def check_ip(target, default=None):
    while True:
        try:
            ip = prompt("Enter {}: ".format(target), default)
            str(IpRange(ip))
        except TypeError:
            print("{} is not a valid IP.".format(ip))
        else:
            return ip


def check_cidr(target, default=None):
    while True:
        try:
            cidr = prompt("Enter {}: ".format(target), default)
            if validate_cidr(cidr):
                pass
            else:
                print("{} is not a valid CIDR.".format(cidr))
            if int(cidr.split("/")[1]) > 27:
                print("{} is too small, use a larger network size.".format(cidr))
            else:
                return cidr
        except Exception:
            pass


def prompt(message, default=None):
    if default:
        return input("{} [{}]: ".format(message, default)) or default
    else:
        return input("{}: ".format(message))


def random_string(len):
    system_random = random.SystemRandom()
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    arr = [system_random.choice(chars) for i in range(len)]
    return "".join(arr)


def get_mfa_type():
    while True:
        mfa_resp = prompt("Will you be using MFA: (y/N) ", default="N")
        if mfa_resp == "y" or mfa_resp == "Y":
            while True:
                mfa_type = prompt(
                    "What MFA provider: (duo/okta/Cancel) ", default="Cancel"
                )
                mfa_type = mfa_type.lower()
                if mfa_type == "duo" or mfa_type == "okta":
                    return mfa_type
                elif mfa_type == "cancel":
                    return ""
                else:
                    print("Please enter `duo`, `okta`, or `Cancel`")
        elif mfa_resp == "n" or mfa_resp == "N":
            return ""
        else:
            print("Please enter `y` or `n`")


def get_duo_data():
    host = prompt("DUO api host, e.g. api-XXXXXXXX.duosecurity.com")
    ikey = prompt("DUO integration key")
    skey = prompt("DUO secret key")
    return {"api_host": host, "ikey": ikey, "skey": skey}


def get_okta_data():
    hostname = prompt("OKTA api hostname, e.g. XXXXXXXX.okta.com")
    apikey = prompt("OKTA api key")
    return {"hostname": hostname, "apikey": apikey}


def is_gce():
    try:
        response = requests.get(METADATA_BASE_URL, timeout=0.1)
        try:
            return response.headers["Metadata-Flavor"] == "Google"
        finally:
            response.close()
    except Exception:
        return False


def gather_user_data_prompt():
    data = {}

    data["psk"] = prompt("Enter PSK", default=random_string(32))
    data["dns_primary"] = check_ip("Primary DNS", "1.1.1.1")
    data["dns_secondary"] = check_ip("Secondary DNS", "1.0.0.1")
    data["l2tp_cidr"] = check_cidr("L2TP IPv4 range (CIDR)", "10.11.12.0/24")
    data["xauth_cidr"] = check_cidr("XAUTH IPv4 range (CIDR)", "10.11.13.0/24")

    mfa_type = get_mfa_type()
    data["mfa_type"] = mfa_type
    if mfa_type == "duo":
        data["duo_config"] = get_duo_data()
    elif mfa_type == "okta":
        data["okta_config"] = get_okta_data()

    data["foxpass_api_key"] = prompt("Foxpass API Key")

    require_groups = prompt("Limit to groups (comma-separated)")

    if require_groups:
        data["require_groups"] = require_groups.split(",")

    return data


def gather_user_data_s3(s3_url):
    import boto3

    parts = urlparse(s3_url)

    if parts.scheme != "s3":
        raise Exception("Must use s3 url scheme")

    bucket_name = parts.netloc
    path = parts.path.lstrip("/")

    s3 = boto3.resource("s3")
    obj = s3.Object(bucket_name, path)
    data = obj.get()["Body"].read().decode("utf-8")

    config = json.loads(data)

    # if it has 'local_cidr', then use that value for l2tp_cidr
    local_cidr = config.pop("local_cidr", None)
    if local_cidr:
        config["l2tp_cidr"] = local_cidr

    return config


def gather_user_data_file(filename):
    config = json.load(open(filename))

    # if it has 'local_cidr', then use that value for l2tp_cidr
    local_cidr = config.pop("local_cidr", None)
    if local_cidr:
        config["l2tp_cidr"] = local_cidr

    return config


def get_machine_data():
    data = {}

    data["radius_secret"] = random_string(16)

    data["is_gce"] = is_gce()

    if data["is_gce"]:
        headers = {"Metadata-Flavor": "Google"}
        google_path = "computeMetadata/v1/instance/network-interfaces/0/"
        data["public_ip"] = requests.get(
            METADATA_BASE_URL + google_path + "access-configs/0/external-ip",
            headers=headers,
            timeout=0.1,
        ).text
        data["private_ip"] = requests.get(
            METADATA_BASE_URL + google_path + "ip", headers=headers, timeout=0.1
        ).text
    else:
        token_headers = None
        http_headers = {
            "X-aws-ec2-metadata-token-ttl-seconds": "600",
            "content-type": "application/json",
        }
        token = requests.put(
            METADATA_BASE_URL + "latest/api/token", timeout=0.1, headers=http_headers
        ).text
        if token:
            token_headers = {
                "X-aws-ec2-metadata-token": token,
                "content-type": "application/json",
            }
        data["public_ip"] = requests.get(
            METADATA_BASE_URL + "latest/meta-data/public-ipv4",
            timeout=0.1,
            headers=token_headers,
        ).text
        data["private_ip"] = str(socket.gethostbyname_ex(socket.gethostname())[2][0])

    data["interface"] = get_adapter(data["private_ip"])

    return data


def get_adapter(private_ip):
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        for ip in adapter.ips:
            if ip.ip == private_ip:
                return adapter.nice_name


def modify_etc_hosts(data):
    private_ip = data["private_ip"]
    hostname = socket.gethostname()

    hosts = Hosts()
    new_entry = HostsEntry(entry_type="ipv4", address=private_ip, names=[hostname])
    hosts.add([new_entry])
    hosts.write()


def config_vpn(data):
    context = {
        "PSK": data["psk"],
        "DNS_PRIMARY": data["dns_primary"],
        "DNS_SECONDARY": data["dns_secondary"],
        "PUBLIC_IP": data["public_ip"],
        "PRIVATE_IP": data["private_ip"],
        "INTERFACE": data["interface"],
        "RADIUS_SECRET": data["radius_secret"],
        "API_KEY": data["foxpass_api_key"],
        "API_HOST": data.get("foxpass_api_url", "https://api.foxpass.com"),
    }

    if "require_groups" in data:
        context["REQUIRE_GROUPS"] = ",".join(data["require_groups"])

    if "mfa_type" in data:
        context["MFA_TYPE"] = data.get("mfa_type")

    if "duo_config" in data:
        context.update(
            {
                "DUO_API_HOST": data["duo_config"].get("api_host"),
                "DUO_IKEY": data["duo_config"].get("ikey"),
                "DUO_SKEY": data["duo_config"].get("skey"),
            }
        )

    if "okta_config" in data:
        context.update(
            {
                "OKTA_HOSTNAME": data["okta_config"].get("hostname"),
                "OKTA_APIKEY": data["okta_config"].get("apikey"),
            }
        )

    l2tp_cidr = data.get("l2tp_cidr")
    if l2tp_cidr:
        l2tp_ip_range_obj = IpRange(data["l2tp_cidr"])
        l2tp_ip_range = "{}-{}".format(l2tp_ip_range_obj[10], l2tp_ip_range_obj[-6])
        l2tp_local_ip = l2tp_ip_range_obj[1]
        context.update(
            {
                "L2TP_IP_RANGE": l2tp_ip_range,
                "L2TP_LOCAL_IP": l2tp_local_ip,
                "L2TP_CIDR": l2tp_cidr,
            }
        )

    xauth_cidr = data.get("xauth_cidr")
    if xauth_cidr:
        xauth_ip_range_obj = IpRange(data["xauth_cidr"])
        xauth_ip_range = "{}-{}".format(xauth_ip_range_obj[10], xauth_ip_range_obj[-6])
        xauth_local_ip = xauth_ip_range_obj[1]

        context.update(
            {
                "XAUTH_IP_RANGE": xauth_ip_range,
                "XAUTH_CIDR": xauth_cidr,
            }
        )

    file_list = {
        "ipsec.secrets": "/etc/",
        "iptables.rules": "/etc/",
        "options.xl2tpd": "/etc/ppp/",
        "xl2tpd.conf": "/etc/xl2tpd/",
        "ipsec.conf": "/etc/",
        "foxpass-radius-agent.conf": "/etc/",
        "servers": "/etc/radiusclient/",
        "pam_radius_auth.conf": "/etc/",
    }

    # initialize jinja to process conf files
    env = Environment(
        loader=FileSystemLoader("/opt/templates"), keep_trailing_newline=True
    )

    files = {}
    for filename, dir in file_list.items():
        path = os.path.join(dir, filename)
        template = env.get_template(filename)
        with open(path, "w") as f:
            rendered = template.render(**context)
            f.write(rendered)

    commands = ["xl2tpd", "ipsec", "foxpass-radius-agent"]
    call(["/sbin/sysctl", "-p"])
    # set /etc/ipsec.secrets and foxpass-radius-agent.conf to be owned and only accessible by root
    # chmod 0o600 is r/w owner
    # chown 0 is set user to root
    # chown 65534 is set user to nobody:nogroup
    chmod("/etc/ipsec.secrets", 0o600)
    chown("/etc/ipsec.secrets", 0, 0)
    chmod("/etc/foxpass-radius-agent.conf", 0o600)
    chown("/etc/foxpass-radius-agent.conf", 65534, 65534)
    call("/sbin/iptables-restore < /etc/iptables.rules", shell=True)
    call("/usr/sbin/netfilter-persistent save", shell=True)
    call(["/usr/bin/systemctl", "enable", "ipsec.service"], shell=False)
    for command in commands:
        call(["/usr/bin/systemctl", "stop", command], shell=False)
        call(["/usr/bin/systemctl", "start", command], shell=False)


def main():
    # only allowed argument is pointer to json file on-disk or in s3
    if len(sys.argv) > 1:
        if sys.argv[1].startswith("s3:"):
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


if __name__ == "__main__":
    main()
