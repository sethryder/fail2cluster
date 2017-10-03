#!/usr/bin/python -W ignore::DeprecationWarning

#config
default_ban_timeout = 86400
aws_access_key = ""
aws_secret_key = ""
dynamodb_ban_table = "fail2ban_banned_ips"
dynamodb_whitelist_table = "fail2ban_whitelist_ips"
dynamodb_auditlog_table = "fail2ban_audit_log"
#nginx settings
nginx_enabled = False
nginx_reload_command = "systemctl reload nginx"
nginx_deny_file = "/etc/nginx/deny.conf"
#aws waf settings
waf_enabled = True
waf_ip_set = ""

import boto3
import botocore
import datetime
import hashlib
import getopt
import json
import operator
import os
import socket
import sys
import time
import uuid
from boto3.dynamodb.conditions import Key, Attr
from subprocess import Popen, PIPE
from string import Template

def usage(opt = 'all'):
    if opt == 'ban':
        print 'Usage: fail2cluster.py ban <ip> [<expires>]'
        print ''
    elif opt == 'unban':
        print 'Usage: fail2cluster.py unban <ip>'
        print ''
    else:
        print 'Usage: fail2cluster.py (option)'
        print ''
        print '-b, --ban <ip> [<seconds> "<note>"]       Ban an IP. Optional: How many seconds until the IP expires, also accepts "never". Can also include a note.'
        print '-u, --unban <ip>                         Unban an IP.'
        print '-w, --whitelist <ip> ["<note>"]          Whitelist an IP. Will also unban the IP if it\'s banned.'
        print '-r, --unwhitelist <ip>                   Remove an IP from the whitelist.'
        print '-l, --list-bans                          List all banned IPs and when they expire.'
        print '-l, --list-whitelisted-ips               List all whitelisted IPs and any included notes.'
        print '-n, --nginx-format-list                  Write bans to a specified file that can be loaded by nginx.'
        print '-h, --help                               Prints out this usage. You are looking at it now!'
        print ''

def ban_ip(ip, expires, note):
    now = int(time.time())
    validate_ip(ip)
    dynamodb = init_aws_dynamodb(dynamodb_ban_table)

    if expires == 'never':
        ttl = 'never'
    else:
        ttl = int(time.time()) + int(expires)

    if check_ip_exists(ip):
        print ip + " is already banned."
        return False

    if check_ip_whitelisted(ip):
        print ip + " is whitelisted, not banning."
        return False

    if waf_enabled:
        waf_ban_ip(ip)

    dynamodb.put_item(
       Item={
            'ip': ip,
            'created': now,
            'expires': ttl,
            'note': note
        }
    )

    if nginx_enabled:
        write_nginx_deny_list(nginx_deny_file)

    audit_log(ip, 'add', now, ttl, note)
    print "Added " + ip + " to ban list."
    return True

def unban_ip(ip, note=' '):
    validate_ip(ip)
    dynamodb = init_aws_dynamodb(dynamodb_ban_table)

    if not check_ip_exists(ip):
        print ip + " is not banned."
        return False

    if waf_enabled:
        waf_unban_ip(ip)

    dynamodb.delete_item(Key={'ip': ip})

    if nginx_enabled:
        write_nginx_deny_list(nginx_deny_file)

    audit_log(ip, 'remove', note="expired")
    print ip + " has been removed."
    return True

def whitelist_ip(ip, note):
    validate_ip(ip)
    now = int(time.time())
    dynamodb = init_aws_dynamodb(dynamodb_whitelist_table)

    if check_ip_whitelisted(ip):
        print ip + " is already whitelisted."
        return False

    if check_ip_exists(ip):
        print ip + " is banned, removing from ban list first."
        unban_ip(ip)

    dynamodb.put_item(
       Item={
            'ip': ip,
            'created': now,
            'note': note,
        }
    )

    print "Added " + ip + " to whitelist."
    return True

def unwhitelist_ip(ip):
    validate_ip(ip)
    dynamodb = init_aws_dynamodb(dynamodb_whitelist_table)

    if not check_ip_whitelisted(ip):
        print ip + " is not whitelisted."
        return False

    dynamodb.delete_item(Key={'ip': ip})

    print "Removed " + ip + " from whitelist."
    return True

def check_ip_exists(ip):
    table = init_aws_dynamodb(dynamodb_ban_table)
    response = table.query(
        KeyConditionExpression=Key('ip').eq(ip)
    )
    if response['Count'] > 0:
        return True
    else:
        return False

def check_ip_whitelisted(ip):
    table = init_aws_dynamodb(dynamodb_whitelist_table)
    response = table.query(
        KeyConditionExpression=Key('ip').eq(ip)
    )
    if response['Count'] > 0:
        return True
    else:
        return False

def init_aws_waf():
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key
    )
    waf = session.client('waf')
    return waf

def init_aws_dynamodb(table):
    dynamodb = boto3.resource('dynamodb',
        region_name='us-east-1',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key
    )
    table = dynamodb.Table(table)
    return table

def waf_ban_ip(ip):
    validate_ip(ip)
    client = init_aws_waf()
    change_token = client.get_change_token()
    try:
        response = client.update_ip_set(
            IPSetId=waf_ip_set,
            ChangeToken=change_token['ChangeToken'],
            Updates=[
                {
                    'Action': 'INSERT',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': ip + '/32'
                    }
                },
            ]
        )
    except botocore.exceptions.ClientError as e:
        print("Unable to ban IP, error: " + str(e))

def waf_unban_ip(ip):
    validate_ip(ip)
    client = init_aws_waf()
    change_token = client.get_change_token()
    try:
        response = client.update_ip_set(
            IPSetId=waf_ip_set,
            ChangeToken=change_token['ChangeToken'],
            Updates=[
                {
                    'Action': 'DELETE',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': ip + '/32'
                    }
                },
            ]
        )
    except botocore.exceptions.ClientError as e:
        print("Unable to ban IP, error: " + str(e))


def remove_expired_ips():
    now = int(time.time())

    table = init_aws_dynamodb(dynamodb_ban_table)
    response = table.scan(
        FilterExpression=Attr('expires').lt(now)
    )
    expired_ips = response['Items']

    for ip in expired_ips:
        unban_ip(ip['ip'], 'expired')

def list_banned_ips():
    dynamodb = init_aws_dynamodb(dynamodb_ban_table)

    response = dynamodb.scan()
    banned_ips = response['Items']

    total = response['Count']
    print str(total) + " banned IP(s):"

    for ip in banned_ips:
        ip_len = len(ip['ip'])
        friendly_ip = ip['ip']
        if ip_len is not 15:
            required_spaces = 15 - ip_len
            friendly_ip += ' ' * required_spaces
        if ip['expires'] != 'never':
            expires = datetime.datetime.fromtimestamp(ip['expires'])
            friendly_date = expires.strftime('%Y-%m-%d %H:%M:%S')
        else:
            friendly_date = 'Never'
        print friendly_ip + " (Expires: " + friendly_date + ")"

def list_whitelisted_ips():
    dynamodb = init_aws_dynamodb(dynamodb_whitelist_table)

    response = dynamodb.scan()
    whitelisted = response['Items']

    total = response['Count']
    print str(total) + " whitelisted IP(s):"

    for ip in whitelisted:
        ip_len = len(ip['ip'])
        friendly_ip = ip['ip']
        if ip_len is not 15:
            required_spaces = 15 - ip_len
            friendly_ip += ' ' * required_spaces
        if ip['note'] != ' ':
            friendly_note = ip['note']
        else:
            friendly_note = 'None'
        print friendly_ip + " (Note: " + friendly_note + ")"

def audit_log(ip, action, created=' ', expires=' ', note=' '):
    dynamodb = init_aws_dynamodb(dynamodb_auditlog_table)
    uid = uuid.uuid4()
    action_time = int(time.time())

    if not created:
        created = int(time.time())

    dynamodb.put_item(
       Item={
            'ip': ip,
            'action': action,
            'action_time': action_time,
            'created': created,
            'expires': expires,
            'note': note
        }
    )

def get_nginx_deny_list():
    dynamodb = init_aws_dynamodb(dynamodb_ban_table)
    denied_ips = ""

    response = dynamodb.scan()
    banned_ips = response['Items']

    for ip in banned_ips:
        denied_ips += "deny " + ip['ip'] + ";\n"

    return denied_ips

def write_nginx_deny_list(nginx_deny_file):
    banned_ips = get_nginx_deny_list()

    new_hash = hashlib.md5(banned_ips).hexdigest()
    current_hash = file_hash(nginx_deny_file)

    if new_hash != current_hash:
        print "Banned IP list has changed, writing new deny file."
        target = open(nginx_deny_file, 'w')
        target.truncate()
        target.write(banned_ips)
        target.close()

        print "Reloading nginx."
        reload_nginx()
        return True
    else:
        print "Banned IP list not changed, finished."
        return False

def reload_nginx():
    print "Reloading Nginx"
    p = Popen(nginx_reload_command, shell=True, stdout=PIPE)
    output = p.communicate()[0]

    if p.returncode != 0:
        print "Error reloading nginx! Return code: " + p.returncode + ", Command: " + reload_command
        return False
    else:
        print "Reloaded Nginx"
        return True

def file_hash(conf_file):
    if os.path.isfile(conf_file):
        with open(conf_file) as conf_file:
            denied_ips = conf_file.read()
            file_hash = hashlib.md5(denied_ips).hexdigest()
        return file_hash
    else:
        return False

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        print '"' + ip + '" is not a valid IP address.'
        sys.exit()
        return False
    return False

def run():
    ran = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "bulhnrwt", [
          "ban",
          "unban",
          "whitelist",
          "unwhitelist",
          "list-bans",
          "list-whitelisted-ips"
          "nginx-format-list",
          "help"])
    except getopt.GetoptError, err:
        print str(err) # will print something like "option -z not recognized"
        usage()
        sys.exit(2)
    for opt, arg in opts:
        ran = True
        if opt in ("-b", "--ban"):
            if len(args) < 1 or len(args) > 3:
                usage('ban')
            expires = default_ban_timeout
            note = ' '
            if len(args) >= 2: expires = args[1]
            if len(args) == 3: note = args[2]
            ban_ip(args[0], expires, note)
            remove_expired_ips()
        elif opt in ("-u", "--unban"):
            if len(args) != 1:
                usage('unban')
            unban_ip(args[0])
            remove_expired_ips()
        elif opt in ("-w", "--whitelist"):
            if len(args) < 1 or len(args) > 2:
                usage('whitelist')
            note = ''
            if len(args) == 2: note = args[1]
            whitelist_ip(args[0], note)
            remove_expired_ips()
        elif opt in ("-r", "--unwhitelist"):
            if len(args) != 1:
                usage('unwhitelist')
            unwhitelist_ip(args[0])
            remove_expired_ips()
        elif opt in ("-l", "--list-bans"):
            list_banned_ips()
            remove_expired_ips()
        elif opt in ("-t", "--list-whitelisted-ips"):
            list_whitelisted_ips()
            remove_expired_ips()
        elif opt in ("-n", "--nginx-format-list"):
            write_nginx_deny_list(nginx_deny_file)
            remove_expired_ips()
        elif opt in ("-h", "--help"):
            usage()
            remove_expired_ips()
        else:
           assert False, "unhandled option"

    if not ran:
        usage()

if __name__ == "__main__":
    run()
