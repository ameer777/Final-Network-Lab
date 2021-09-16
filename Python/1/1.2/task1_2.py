#!/usr/bin/env python3
from scapy.all import *

ip = IP()
ip.dst = '10.9.0.5'
ip.src = '9.8.7.6'

icmp = ICMP()
packet = ip/icmp
send(packet)