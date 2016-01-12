#! /usr/bin/env python
# -*- coding:utf-8 -*-

"""
function: use scapy scan the local network by arp request
by janes, 2016.01.12
"""

import sys
from scapy.all import *

def arpscan(ip):
    """
        ip[str]: "192.168.0.1" or "192.168.0.0/24"
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(hwtype=1,ptype=0x0800,op=1,pdst=ip)
    ans, unans = srp(pkt, timeout=5)
    print("")
    print("scanning {0},the number is:{1}".format(ip, len(ans)+len(unans)))
    print("the live computer number is:{}".format(len(ans)))
    ans.nsummary(lambda(s,r):r.sprintf("%Ether.src%: %ARP.psrc%"))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
            Usage: sudo python arpscan.py <ip>\n
            ip can be "192.168.0.1" or "192.168.0.0/24"
            """)
        sys.exit(-1)
    ip = str(sys.argv[1])
    arpscan(ip)
