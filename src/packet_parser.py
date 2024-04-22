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


def parse_packet(packet):
    summary_lines = []

    if packet.haslayer(IP):
        summary_lines.append(f"IP: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer(TCP):
        summary_lines.append(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
    if packet.haslayer(UDP):
        summary_lines.append(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
    if packet.haslayer(DNS):
        dns_query = ' '.join(q.qname.decode('utf-8') for q in packet[DNS].qd) if packet[DNS].qd else "No Queries"
        summary_lines.append(f"DNS Queries: {dns_query}")
    if packet.haslayer(DHCP):
        dhcp_types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}
        dhcp_type = dhcp_types.get(packet[DHCP].options[0][1], "Other")
        summary_lines.append(f"DHCP: {dhcp_type}")
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        http_layer = packet[HTTPRequest] if packet.haslayer(HTTPRequest) else packet[HTTPResponse]
        summary_lines.append(f"HTTP: {http_layer.Method.decode()} {http_layer.Path.decode()}")
    if packet.haslayer(NTP):
        ntp_layer = packet[NTP]
        summary_lines.append(f"NTP Version: {ntp_layer.version}")
    if packet.haslayer(Raw):
        payload = packet[Raw].load[:DEFAULT_PAYLOAD_SIZE]
        payload_hexdump = hexdump(payload, dump=True)
        summary_lines.append("Payload (hexdump):")
        summary_lines.append(payload_hexdump)

    return "\n".join(summary_lines)
