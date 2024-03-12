from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import hexdump


def parse_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP: {ip_layer.src} -> {ip_layer.dst}")

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport}")
        # Print TCP payload
        if tcp_layer.payload:
            payload = bytes(tcp_layer.payload)
            print(hexdump(payload[:100]))  # Limit to first 60 bytes

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"UDP: {udp_layer.sport} -> {udp_layer.dport}")
        # Print UDP payload
        if udp_layer.payload:
            payload = bytes(udp_layer.payload)
            print(hexdump(payload[:100]))  # Limit to first 60 bytes
