#!/usr/bin/python

#       blockDoH.py - a program to read a list of DNS resolvers that run DNS over HTTPS
#       and create iptables rules to block access to them.
#
#       Some code here - notably _do_cmd() and associated code where that is invoked
#       was lifted with only minor modifications from blockhosts.py by 
#       Avinash Chopde <avinash@acm.org>, http://www.aczoom.com/cms/blockhosts/
#
#       The blocklist used is provided by https://dnscrypt.info as a free download.
#       To download it: cd /tmp && wget http://download.dnscrypt.info/dnscrypt-resolvers/json/public-resolvers.json
#       
#       I download it separately so that I don't have to download it every time I run
#       this script (be nice to others' servers).  I have the script that does the downloading running as a cron
#       job once a week, while this script runs whenever my firewall is reloaded, which
#       occurs whenever the VPN is changed and restarted, which could be a few times a day.
#
#       I use this script on a dedicated raspberry pi VPN proxy/gateway that resides exclusively on my IOT VLAN -
#       a fully locked-down VLAN that hosts my smart TV and other untrusted devices while completely
#       isolating them from my main LAN and its sensitive and trusted systems.  Also accessible
#       on that VLAN is a pihole DNS server, which serves DNS to my entire network.
#       
#       The TV is set to get its DNS from the pihole, and to use the VPN proxy as its gateway.  This
#       script then blocks any traffic arriving on the VLAN that is destined for a DNS server that
#       is on the list, prior to its entry into the VPN.  This stops a mechanism for "calling home" that
#       is becoming very common and is not detected or stopped by other techniques.
#
#       The pihole DNS server uses DoH to obtain its DNS, but it accesses the internet over the main LAN,
#       not this IOT VLAN.
#
#       This program is placed in the public domain; use as you see fit.
#
#       This, by the way, is my first python program.  Normally I program C, C++, and PHP among others.
#
#       Author: Jim Locker, jiml@justsosoftware.com
#               August 2020
#

OURDNS = "192.168.24.50"
DNSJSON = "/tmp/public-resolvers.json"

import os
import sys
import json
import re
import dns.resolver
import syslog

def read_json():
    fp = open(DNSJSON, 'r')
    filedata = fp.read()
    return filedata

def find_ip(str) :
    ip = re.findall(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str)
    return ip

def _do_cmd(cmd, expect=None):
    """Executes command, and returns a tuple that is command return
    status if os.WIFEXITED(waitstatus) is true, otherwise returns
    waitstatus as received from commands.getstatusoutput()
    Prints error if expect code is not same as waitstatus
    """
    import commands

    print "Running: ", cmd

    (waitstatus, output) = commands.getstatusoutput(cmd)
    print "   returned waitstatus: ", waitstatus
    if output.strip():
        print "   output: ", output

    if os.WIFEXITED(waitstatus):
        waitstatus = os.WEXITSTATUS(waitstatus)

    if None != expect != waitstatus:
        print "Failed command: %s (%d)\n%s" % (cmd, waitstatus, output)

    return (waitstatus, output)


data=json.loads(read_json())
datalen = len(data)

if datalen > 0:
    cmd = "/sbin/iptables --new blockDoH"
    (waitstatus, output) = _do_cmd(cmd, None)
    if waitstatus != 0:
        # iptables: Chain already exists
        print" ... user-defined chain blockDoH already exists, or error occurred "
    else:
        print" ... created user-defined chain blockDoH"
    cmd = "/sbin/iptables --insert FORWARD -j blockDoH"
    (waitstatus, output) = _do_cmd(cmd, None)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [OURDNS]
    ii=0
    while ii < datalen:
        proto = data[ii]['proto']
        listlen = len(data[ii]['addrs'])

        addr = (data[ii]['addrs'])[listlen - 1]
        useip = find_ip(addr)
        if proto == 'DoH' and useip != []:
            print "addr = ",addr
            cmd = "/sbin/iptables --append blockDoH -i vlan0 -d %s -j DROP" % addr
            (waitstatus, output) = _do_cmd(cmd, None)
        if proto == 'DoH' and useip == [] and addr.find(':') == -1:
            print "calling resolver on ", addr
            try:
                resolv = resolver.query(addr, 'A')
                for ipval in resolv:
                    print "resolv = ",ipval.to_text()
                    cmd = "/sbin/iptables --append blockDoH -i vlan0 -d %s -j DROP" % ipval.to_text()
                    (waitstatus, output) = _do_cmd(cmd, None)
            except: 
                print addr, " did not resolve" 
        ii = ii + 1
    cmd = "/sbin/iptables --append blockDoH -i vlan0 -d 1.1.1.1 -j DROP"
    (waitstatus, output) = _do_cmd(cmd, None)
