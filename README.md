### What it does

This repo helps you create an AMI image that offers a simple IPSEC/L2TP VPN server. Username and password will be checked against [Foxpass](https://www.foxpass.com) (which in-turn syncs with Google Apps) and optionally against [Duo](https://www.duo.com) or [Okta](https://www.okta.com) for two-factor authentication (HIGHLY RECOMMENDED). NOTE: If you use emails for your Duo requests instead of usernames, you must enable username normalization. You can find more info about that setting [here](https://duo.com/docs/creating_applications#username-normalization). If you use Okta instead, Foxpass requires credentials with at least [Group Admin](https://help.okta.com/en/prod/Content/Topics/Security/The_User_Admin_Role.htm?Highlight=group%20admin) privileges in order to check the 2FA API endpoint with Okta.

Note that you don't have to build it. We have ready-to-go, free-of-charge AMIs on the [AWS Marketplace](https://aws.amazon.com/marketplace/pp/B01HMLVKPS).

### How to build it

* Clone this repo
* init and update the submodules:
  * `git submodule init`
  * `git submodule update`
* Download and install Hashicorp's Packer (http://packer.io)
* Put your AWS access key and secret key someplace that Packer [can find them](https://www.packer.io/docs/builders/amazon.html#specifying-amazon-credentials).
* set your region and base AMI (currently designed for Ubuntu 16.04 base images) in foxpass_vpn.json
* run `packer build foxpass_vpn.json`

for Google Cloud Platform :

* Get account file JSON if not building on a GCE instance as [described here](https://www.packer.io/docs/builders/googlecompute.html)
* populate config variables via command line or variable file ([docs](https://www.packer.io/docs/templates/user-variables.html))
* run `packer build gcp_foxpass_vpn.json`

### How to run it

* Instantiate an image with the resulting AMI
  * Make sure it has a public IP address
  * Make sure it is in a security group with the following inbound rules:
    * UDP 500
    * UDP 4500
    * TCP 22 to your IP (for SSH management)
  * (optional, see below) for AWS: setup script can pull config from S3. Set role and user-data as described below.

* When the instance comes up

  ```
  ssh ubuntu@<hostname-or-ip>
  sudo /opt/bin/config.py
  ```

* To automatically pull config from S3 (optional)
  * Set EC2 user-data to

   ```
    #!/bin/bash
    sudo /opt/bin/config.py s3://bucket-name/path/to/config.json
   ```
   This will run the config script on startup, you will not need to run the config script manually.

  * Set EC2 role to a role in IAM that has `ListBucket` and `GetObject` permissions (`GetObjectVersion`, too, if your bucket has versioning enabled) to the above-mentioned bucket and path in S3. (Only required if you choose to automatically pull your config from S3.)
  * Upload the config file with the following format (mfa_type, duo_config, okta_config, and require_groups are optional):

   ```
   {
    "psk": "MAKE_UP_A_SECURE_SHARED_KEY",
    "dns_primary": "8.8.8.8",
    "dns_secondary": "8.8.4.4",
    "local_cidr": "10.11.12.0/24",
    "foxpass_api_key": "PUT_YOUR_FOXPASS_API_KEY_HERE",
    "mfa_type": "duo_OR_okta",
    "duo_config": {"api_host": "API_HOST_FROM_DUO", "skey": "SKEY_FROM_DUO", "ikey": "IKEY_FROM_DUO"},
    "okta_config": {"hostname": "OKTA_HOSTNAME", "apikey": "OKTA_APIKEY"},
    "require_groups": ["group_1", "group_2"] <- optionally requires user to be a member of one of the listed groups
   }
   ```

### How to set up your clients

* [Mac OSX](https://foxpass.readme.io/docs/foxpass-ipsec-vpn-macosx)
* [Windows](https://foxpass.readme.io/docs/foxpass-windows-8-l2tpipsec-setup)

### How to make changes

Pull requests welcome!

* templates/ are the configuration templates that will be updated by the config.py script.
* scripts/ include the config.py script and the static configuration files that need to be installed.
* foxpass-radius-agent/ is a submodule [(See here)](https://github.com/foxpass/foxpass-radius-agent) that contains a radius agent that connects L2TP to Foxpass and Duo authentication APIs.

### Thank you
* Huge thank-you to [Travis Theune](https://github.com/ttheune) who was an instrumental collaborator throughout the design, implementation, and testing.
* Based on the [work](https://github.com/hwdsl2/setup-ipsec-vpn/blob/master/vpnsetup.sh) of Lin Song (Copyright 2014-2016), which was based on the [work](https://github.com/sarfata/voodooprivacy/blob/master/voodoo-vpn.sh) of Thomas Sarlandie (Copyright 2012)
