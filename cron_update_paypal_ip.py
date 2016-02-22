import os
import sys
from datetime import datetime
from time import time
import socket
from boto import ec2

# Version, :/
VERSION = '2'
# Shell Defaults
RC = 0
TIME_PATTERN = '%Y-%m-%d %H:%M:%S'

# Production
SECURITY_GROUP_APP = "sg-XXXXXXXX"
SECURITY_GROUP_WEB = "sg-XXXXXXXX"
PAYPAL_API_NAME = "api-3t.paypal.com"
PAYPAL_3T_NAME = "api.paypal.com"


# Core Common Function
def check_RC(**kwargs):
    if RC != 0:
        fail("Unknown Error")


def info(message):
    print "[INFO]: %s: " % datetime.now().strftime(TIME_PATTERN) + message


def success(message):
    print "[PASS]: %s: " % datetime.now().strftime(TIME_PATTERN) + message


def fail(message):
    print "[FAIL]: %s: " % datetime.now().strftime(TIME_PATTERN) + message
    print "Exiting Script!"
    exit(1)


def warn(message):
    print "[WARN]: %s: " % datetime.now().strftime(TIME_PATTERN) + message


def print_version():
    info("%s: Script version: %s" % (str(sys.argv[0]), VERSION))


def get_ips(domain_name):
    ips = socket.gethostbyname_ex(domain_name)
    info("Resolved IP for %s " % domain_name)
    info(str(ips[2]))
    return ips[2]


def get_all_security_groups(conn):
    return conn.get_all_security_groups()


def get_security_group(sgs, sg_name):
    for sg in sgs:
        if sg.name == sg_name:
            return sg


def get_paypal_ip_from_sg(sg):
    rules = sg.rules_egress
    ips = []
    paypal_ips = []
    for rule in rules:
        if rule.to_port == "443":
            ips = rule.grants
            break
    for ip in ips:
        if str(ip).startswith("173"):
            paypal_ips.append(ip)
    info("Current paypal IPs %s" % str(paypal_ips))
    return paypal_ips


def conv_aws_ips_to_array(ips):
    new_arr = []
    for ip in ips:
        new_arr.append(str(ip).replace('/32', ''))
    return new_arr


def get_ips_to_add(paypal_web_ips, paypal_aws_ips):
    ips_to_add = []
    for paypal_web_ip in paypal_web_ips:
        if paypal_web_ip not in paypal_aws_ips:
            ips_to_add.append(paypal_web_ip)
    return ips_to_add


def get_ips_to_remove(paypal_web_ips, paypal_aws_ips):
    ips_to_remove = []
    for paypal_aws_ip in paypal_aws_ips:
        if paypal_aws_ip not in paypal_web_ips:
            ips_to_remove.append(paypal_aws_ip)
    return ips_to_remove


def add_ips_to_sg(conn, sg, ips):
    for ip in ips:
        info("Adding IP %s to group %s" % (sg, str(ip)))
        conn.authorize_security_group_egress(sg, 'tcp', from_port=443, to_port=443, cidr_ip="%s/32" % ip)


def remove_ips_from_sg(conn, sg, ips):
    for ip in ips:
        info("Removing IP %s from group %s" % (sg, str(ip)))
        conn.revoke_security_group_egress(sg, 'tcp', from_port=443, to_port=443, cidr_ip="%s/32" % ip)


def analyse_and_update_IP(conn):
    # Get Paypal IPs from paypal.com
    api_ips = get_ips(PAYPAL_API_NAME)
    t_ips = get_ips(PAYPAL_3T_NAME)

    # Combine IPs
    paypal_web_ips = api_ips + t_ips

    # Get Security Groups
    sgs = get_all_security_groups(conn)
    app_sg = get_security_group(sgs, "estore2-app")
    web_sg = get_security_group(sgs, "estore2-web")

    # Get Paypal IPs from AWS
    paypal_ips_from_aws = get_paypal_ip_from_sg(app_sg)

    # Conv paypal ip to str-array
    paypay_aws_ips = conv_aws_ips_to_array(paypal_ips_from_aws)

    # Find IPs to remove from sg
    ips_to_remove = get_ips_to_remove(paypal_web_ips=paypal_web_ips, paypal_aws_ips=paypay_aws_ips)

    # Find IPs to add to sg
    ips_to_add = get_ips_to_add(paypal_web_ips=paypal_web_ips, paypal_aws_ips=paypay_aws_ips)

    add_ips_to_sg(conn=conn, sg=SECURITY_GROUP_APP, ips=ips_to_add)
    remove_ips_from_sg(conn=conn, sg=SECURITY_GROUP_APP, ips=ips_to_remove)
    add_ips_to_sg(conn=conn, sg=SECURITY_GROUP_WEB, ips=ips_to_add)
    remove_ips_from_sg(conn=conn, sg=SECURITY_GROUP_WEB, ips=ips_to_remove)


# Real Work is done here.
def main(argv):
    if len(sys.argv) > 1:
        if sys.argv[1] == '-v':
            print_version()
            exit(0)
    # Export key,id as ENV Variables. Best option is to use AWS Roles. Keys are deprecated.
    conn = ec2.connect_to_region("ap-southeast-2", aws_access_key_id="XXXXXXX",
                                 aws_secret_access_key="XXXXXXXX")
    analyse_and_update_IP(conn)
    print_version()
    success("Script completed successfully.")
    exit(0)


if __name__ == "__main__":
    main(sys.argv)
