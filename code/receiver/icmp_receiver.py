import scapy

# Implement your ICMP receiver here

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff

def handle_packet(packet):

    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[IP].ttl == 1:
            packet.show()


sniff(filter="icmp", prn=handle_packet)
