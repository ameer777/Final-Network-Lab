#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-b0536f20c0fc', filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)