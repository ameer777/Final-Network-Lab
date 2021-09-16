#!/usr/bin/env python3
from scapy.all import *

ECHO_REQUEST = 8
ECHO_REPLY = 0

def spoof_packet(pkt):
        if ICMP in pkt and pkt[ICMP].type == ECHO_REQUEST:
                ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                icmp = ICMP(type=ECHO_REPLY, seq=pkt[ICMP].seq, id=pkt[ICMP].id)
                payload = pkt[Raw].load

                spoofedpkt = ip/icmp/payload
                send(spoofedpkt)
        pkt.show()

pkt = sniff(iface='br-b0536f20c0fc', filter='icmp and src host 10.9.0.5', prn=spoof_packet)