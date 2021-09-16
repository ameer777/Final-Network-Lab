#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-b0536f20c0fc', filter='icmp', prn=print_pkt)