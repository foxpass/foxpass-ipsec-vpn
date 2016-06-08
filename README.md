### What it does

This repo help you create an AMI image that offers a simple IPSEC/L2TP VPN server. Authentication will be checked against [Foxpass](https://www.foxpass.com) and optionally against [Duo](https://www.duo.com) for two-factor authentication.

Note that you don't have to build it. We have ready-to-go AMIs on the AWS Marketplace.

### How to build it

* Download and install Hashicorp's Packer (http://packer.io)
* run `packer build foxpass_vpn.json`

### How to run it

* Instantiate an image with the resulting AMI
  * Make sure it has a public IP address
  * Make sure it is in a security group with the following rules:
    * UDP 500
    * UDP 4500
    * TCP 22 to your IP (for SSH management)
* When the instance comes up, run `sudo /opt/bin/config.py`

### How to set up your clients

* [Mac OSX](https://foxpass.readme.io/docs/foxpass-ipsec-vpn-macosx)

### How to make changes

* templates/ are the configuration templates that will be updated by the config.py script.
* scripts/ include the config.py script and the static configuration files that need to be installed.
* radius/ is the radius agent that connects L2TP to Foxpass and Duo authentication APIs.

### Thank you
* Huge thank-you to [Travis Theune](https://github.com/ttheune) who was an instrumental collaborator throughout the design, implementation, and testing.
* Based on the [work](https://github.com/hwdsl2/setup-ipsec-vpn/blob/master/vpnsetup.sh) of Lin Song (Copyright 2014-2016), which was based on the [work](https://github.com/sarfata/voodooprivacy/blob/master/voodoo-vpn.sh) of Thomas Sarlandie (Copyright 2012)
