# blockDoH
Block DNS over HTTPS traffic
       blockDoH.py - a program to read a list of DNS resolvers that run DNS over HTTPS
       and create iptables rules to block access to them.

       Some code here - notably _do_cmd() and associated code where that is invoked
       was lifted with only minor modifications from blockhosts.py by 
       Avinash Chopde <avinash@acm.org>, http://www.aczoom.com/cms/blockhosts/

       The blocklist used is provided by https://dnscrypt.info as a free download.
       To download it: cd /tmp && wget http://download.dnscrypt.info/dnscrypt-resolvers/json/public-resolvers.json
       
       I download it separately so that I don't have to download it every time I run
       this script (be nice to others' servers).  I have the script that does the downloading running as a cron
       job once a week, while this script runs whenever my firewall is reloaded, which
       occurs whenever the VPN is changed and restarted, which could be a few times a day.

       I use this script on a dedicated raspberry pi VPN proxy/gateway that resides exclusively on my IOT VLAN -
       a fully locked-down VLAN that hosts my smart TV and other untrusted devices while completely
       isolating them from my main LAN and its sensitive and trusted systems.  Also accessible
       on that VLAN is a pihole DNS server, which serves DNS to my entire network.
       
       The TV is set to get its DNS from the pihole, and to use the VPN proxy as its gateway.  This
       script then blocks any traffic arriving on the VLAN that is destined for a DNS server that
       is on the list, prior to its entry into the VPN.  This stops a mechanism for "calling home" that
       is becoming very common and is not detected or stopped by other techniques.

       The pihole DNS server uses DoH to obtain its DNS, but it accesses the internet over the main LAN,
       not this IOT VLAN.

       This program is placed in the public domain; use as you see fit.

       This, by the way, is my first python program.  Normally I program C, C++, and PHP among others.

       Author: Jim Locker, jiml@justsosoftware.com
               August 2020


TODO:  This script does not catch ipv6 addresses.  Need to add that.
