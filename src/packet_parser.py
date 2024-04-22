# packet_parser.py
from scapy.all import Raw, hexdump
from settings import DEFAULT_PAYLOAD_SIZE
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.ntp import NTP

# Global dictionary to keep track of packet counts
packet_counts = {
    'IP': 0,
    'TCP': 0,
    'UDP': 0,
    'DNS': 0,
    'DHCP': 0,
    'HTTP': 0,
    'NTP': 0
}


def parse_packet(packet, output_callback):
    if packet.haslayer(IP):
        output_callback(f"IP: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer(TCP):
        output_callback(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
    if packet.haslayer(UDP):
        output_callback(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
    if packet.haslayer(DNS):
        dns_query = ' '.join(q.qname.decode('utf-8') for q in packet[DNS].qd) if packet[DNS].qd else "No Queries"
        output_callback(f"DNS Queries: {dns_query}")
    if packet.haslayer(DHCP):
        dhcp_type = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}.get(packet[DHCP].options[0][1], "Other")
        output_callback(f"DHCP: {dhcp_type}")
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        http_layer = packet[HTTPRequest] if packet.haslayer(HTTPRequest) else packet[HTTPResponse]
        output_callback(f"HTTP: {http_layer.Method.decode()} {http_layer.Path.decode()}")
    if packet.haslayer(NTP):
        output_callback(f"NTP Version: {packet[NTP].version}")
    if packet.haslayer(Raw):
        payload = packet[Raw].load[:DEFAULT_PAYLOAD_SIZE]
        payload_hexdump = hexdump(payload, dump=True)
        output_callback(payload_hexdump)