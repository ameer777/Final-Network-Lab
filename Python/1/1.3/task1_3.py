#!/usr/bin/env python3
from scapy.all import *

ip = IP()
ip.dst = '157.240.195.35'
ip.ttl = 1

icmp = ICMP()
packet = ip/icmp
send(packet)