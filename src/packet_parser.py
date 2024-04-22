# packet_parser.py
from scapy.all import Raw, hexdump
from settings import DEFAULT_PAYLOAD_SIZE, DEFAULT_COLORS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.ntp import NTP
from rich.text import Text
import time


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

# Start time for timestamps
start_time = time.time()

# Packet counter (initialized globally for persistence)
packet_counter = 0

def parse_packet(packet, output_callback):
    global packet_counts, packet_counter

    # Calculate timestamp
    timestamp = time.time() - start_time

    # IP Layer Parsing
    if packet.haslayer(IP):
        packet_counter += 1
        ip_summary = f"[{packet_counter}] ({timestamp:.2f}) IP: {packet[IP].src} -> {packet[IP].dst}"
        output_callback(Text(ip_summary, style=DEFAULT_COLORS['IP']))
        handle_payload(packet, output_callback, 'IP')

    # TCP Layer Parsing
    if packet.haslayer(TCP):
        packet_counter += 1
        tcp_summary = f"[{packet_counter}] ({timestamp:.2f}) TCP: {packet[TCP].sport} -> {packet[TCP].dport}"
        output_callback(Text(tcp_summary, style=DEFAULT_COLORS['TCP']))
        handle_payload(packet, output_callback, 'TCP')

    # UDP Layer Parsing
    if packet.haslayer(UDP):
        packet_counter += 1
        udp_summary = f"[{packet_counter}] ({timestamp:.2f}) UDP: {packet[UDP].sport} -> {packet[UDP].dport}"
        output_callback(Text(udp_summary, style=DEFAULT_COLORS['UDP']))
        handle_payload(packet, output_callback, 'UDP')

    # DNS Layer Parsing
    if packet.haslayer(DNS):
        packet_counter += 1
        dns_summary = f"[{packet_counter}] ({timestamp:.2f}) DNS Queries: {' '.join(q.qname.decode() for q in packet[DNS].qd)}" if packet[DNS].qd else "DNS Queries: No Queries"
        output_callback(Text(dns_summary, style=DEFAULT_COLORS['DNS']))

    # DHCP Layer Parsing
    if packet.haslayer(DHCP):
        packet_counter += 1
        dhcp_summary = f"[{packet_counter}] ({timestamp:.2f}) DHCP: {packet[DHCP].options}"
        output_callback(Text(dhcp_summary, style=DEFAULT_COLORS['DHCP']))

    # HTTP Layer Parsing
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        packet_counter += 1
        http_layer = packet[HTTPRequest] if packet.haslayer(HTTPRequest) else packet[HTTPResponse]
        http_summary = f"[{packet_counter}] ({timestamp:.2f}) HTTP: {http_layer.Method.decode()} {http_layer.Path.decode()}"
        output_callback(Text(http_summary, style=DEFAULT_COLORS['HTTP']))

    # NTP Layer Parsing
    if packet.haslayer(NTP):
        packet_counter += 1
        ntp_summary = f"[{packet_counter}] ({timestamp:.2f}) NTP Version: {packet[NTP].version}"
        output_callback(Text(ntp_summary, style=DEFAULT_COLORS['NTP']))


def handle_payload(packet, output_callback, protocol):
    if packet.haslayer(Raw):
        payload = packet[Raw].load[:DEFAULT_PAYLOAD_SIZE]
        payload_hexdump = hexdump(payload, dump=True)
        output_callback(Text(payload_hexdump, style=DEFAULT_COLORS[protocol]))


def reset_packet_counter():
    global packet_counter
    packet_counter = 0  # Reset the counter to 0
