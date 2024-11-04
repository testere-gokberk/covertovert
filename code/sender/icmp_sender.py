import scapy

# Implement your ICMP sender here

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

def send_icmp_request(target_ip):

    packet = IP(dst=target_ip, ttl=1) / ICMP()
    
    send(packet)


target_ip = "172.18.0.2"

send_icmp_request(target_ip)
