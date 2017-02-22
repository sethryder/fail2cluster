#!/usr/bin/python -W ignore::DeprecationWarning

#config
default_ban_timeout = 86400
redis_hostname = ''
redis_port = 6379
nginx_reload_command = "/etc/init.d/nginx reload"
nginx_deny_file = "/etc/nginx/deny.conf"
waf_enabled = False

import boto3
import botocore
import datetime
import hashlib
import getopt
import json
import os
import redis
import socket
import sys
import time
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
        print '-b, --ban <ip> [<seconds>]               Ban an IP. Optional: How many seconds until the IP expires, also accepts "never".'
        print '-u, --unban <ip>                         Unban an IP.'
        print '-w, --whitelist <ip>                     Whitelist an IP. Will also unban it if it\'s banned.'
        print '-r, --unwhitelist <ip>                   Remove an IP from the whitelist.'
        print '-l, --list-bans                          List all banned IPs and when they expire.'
        print '-n, --nginx-format-list                  Write bans to a specified file that can be loaded by nginx.'
        print '-h, --help                               Prints out this usage. You are looking at it now!'
        print ''

def redis_init():
    try:
        r = redis.StrictRedis(host=redis_hostname, port=redis_port, db=0, socket_timeout=2)
    except redis.ConnectionError:
        sys.exit()
    return r

def ban_ip(ip, expires):
    validate_ip(ip)
    r = redis_init()
    exists = r.zrank('banned_ips', ip)
    whitelisted = r.sismember('whitelisted_ips', ip)

    if expires == 'never':
        ttl = 2147483647
    else:
        ttl = int(time.time()) + expires

    if exists is not None:
        print ip + " is already banned."
        return False

    if whitelisted:
        print ip + " is whitelisted, not banning."
        return False

    if waf_enabled:
        waf_ban_ip(ip)

    r.zadd('banned_ips', ttl, ip)
    print "Added " + ip + " to ban list."
    return True

def unban_ip(ip):
    validate_ip(ip)
    r = redis_init()
    exists = r.zrank('banned_ips', ip)

    if exists is None:
        print ip + " is not banned."
        return False

    if waf_enabled:
        waf_unban_ip(ip)

    r.zrem('banned_ips', ip)
    print ip + " has been removed."
    return True

def whitelist_ip(ip):
    validate_ip(ip)
    r = redis_init()
    exists = r.sismember('whitelisted_ips', ip)
    banned = r.zrank('banned_ips', ip)

    if exists:
        print ip + " is already whitelisted."
        return False

    if banned is not None:
        print ip + " is banned, removing from ban list first."
        unban_ip(ip)

    r.sadd('whitelisted_ips', ip)
    print "Added " + ip + " to whitelist."
    return True

def unwhitelist_ip(ip):
    validate_ip(ip)
    r = redis_init()
    exists = r.sismember('whitelisted_ips', ip)

    if not exists:
        print ip + " is not whitelisted."
        return False

    r.srem('whitelisted_ips', ip)
    print "Removed " + ip + " from whitelist."
    return True

def waf_ban_ip(ip):
    print "waf ban ip"

def waf_unban_ip(ip):
    print "waf unban ip"

def remove_expired_ips():
    r = redis_init()
    now = int(time.time())
    r.zremrangebyscore('banned_ips', 0, now)

def list_ips():
    r = redis_init()
    banned_ips = r.zrange('banned_ips', 0, -1)

    total = len(banned_ips)
    print str(total) + " banned IP(s)"

    for ip in banned_ips:
        print ip

def get_nginx_deny_list():
    r = redis_init()
    ips = r.zrange('banned_ips', 0, -1)
    denied_ips = ""

    for ip in ips:
        denied_ips += "deny " + ip + ";\n"

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
        opts, args = getopt.getopt(sys.argv[1:], "bulhnrw", [
          "ban",
          "unban",
          "whitelist",
          "unwhitelist",
          "list-bans",
          "nginx-format-list",
          "help"])
    except getopt.GetoptError, err:
        print str(err) # will print something like "option -z not recognized"
        usage()
        sys.exit(2)
    for opt, arg in opts:
        ran = True
        if opt in ("-b", "--ban"):
            if len(args) < 1 or len(args) > 2:
                usage('ban')
            ban_ip(args[0], default_ban_timeout)
            write_nginx_deny_list(nginx_deny_file)
            remove_expired_ips()
        elif opt in ("-u", "--unban"):
            if len(args) != 1:
                usage('unban')
            unban_ip(args[0])
            remove_expired_ips()
        elif opt in ("-w", "--whitelist"):
            if len(args) != 1:
                usage('whitelist')
            whitelist_ip(args[0])
            remove_expired_ips()
        elif opt in ("-r", "--unwhitelist"):
            if len(args) != 1:
                usage('unwhitelist')
            unwhitelist_ip(args[0])
            remove_expired_ips()
        elif opt in ("-l", "--list-bans"):
            list_ips()
            remove_expired_ips()
        elif opt in ("-n", "--nginx-format-list"):
            write_nginx_deny_list(nginx_deny_file)
            remove_expired_ips()
        elif opt in ("-h", "--help"):
            usage()
        else:
           assert False, "unhandled option"

    if not ran:
        usage()

if __name__ == "__main__":
    try:
        run()
    except redis.ConnectionError:
        sys.exit()
