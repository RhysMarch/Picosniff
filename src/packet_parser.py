"""
packet_parser.py

This module provides functionalities for parsing network packets captured via Scapy.
It supports multiple protocols including IP, TCP, UDP, DNS, DHCP, HTTP, and NTP. The
module updates global counters and statistics based on the traffic observed and
formats this data into human-readable summaries using the Rich library for display
purposes.

Features:
- Detailed parsing of packets with support for various network layers and protocols.
- Tracking of packet counts for different protocols, which can be displayed and reset.
- Formatting packet data for display, including hex dumps of payloads for detailed inspection.

Functions:
- parse_packet(packet, output_callback, start_time): Analyses the packet and uses the output_callback to display formatted information.
- handle_payload(packet, output_callback, protocol): Handles packet payloads and provides formatted output, typically a hex dump.
- reset_packet_counter(): Resets the global packet counter to zero.
- reset_packet_counts(): Resets all protocol-specific packet counts to zero.

Global Variables:
- packet_counts: A dictionary tracking the counts of packets for supported protocols.
- packet_counter: A counter tracking the total number of packets parsed.

Usage:
This module is intended to be used where packet capture data needs to be parsed, formatted, and displayed in real-time. It integrates directly with systems
that capture packets using Scapy and can output data either to the console or to a UI via provided callback functions.

Example:
To use parse_packet function, ensure you provide a packet object received from Scapy, a callback function to handle strings of formatted packet summaries,
and a start time for relative timing information.
"""
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

# Packet counter (initialised globally for persistence)
packet_counter = 0


def parse_packet(packet, output_callback, start_time):
    global packet_counts, packet_counter  # Modify global

    # Calculate timestamp (reset if sniffing starts)
    current_time = time.time()
    if not hasattr(parse_packet, 'previous_start_time') or current_time < parse_packet.previous_start_time:
        start_time = current_time  # Reset start_time if sniffing restarts
    parse_packet.previous_start_time = current_time

    timestamp = current_time - start_time

    # IP Layer Parsing
    if packet.haslayer(IP):
        packet_counter += 1
        packet_counts['IP'] += 1
        ip_summary = f"[{packet_counter}] ({timestamp:.2f}) IP: {packet[IP].src} -> {packet[IP].dst}"
        output_callback(Text(ip_summary, style=DEFAULT_COLORS['IP']))
        handle_payload(packet, output_callback, 'IP')

    # TCP Layer Parsing
    if packet.haslayer(TCP):
        packet_counter += 1
        packet_counts['TCP'] += 1
        tcp_summary = f"[{packet_counter}] ({timestamp:.2f}) TCP: {packet[TCP].sport} -> {packet[TCP].dport}"
        output_callback(Text(tcp_summary, style=DEFAULT_COLORS['TCP']))
        handle_payload(packet, output_callback, 'TCP')

    # UDP Layer Parsing
    if packet.haslayer(UDP):
        packet_counter += 1
        packet_counts['UDP'] += 1
        udp_summary = f"[{packet_counter}] ({timestamp:.2f}) UDP: {packet[UDP].sport} -> {packet[UDP].dport}"
        output_callback(Text(udp_summary, style=DEFAULT_COLORS['UDP']))
        handle_payload(packet, output_callback, 'UDP')

    # DNS Layer Parsing
    if packet.haslayer(DNS):
        packet_counter += 1
        packet_counts['DNS'] += 1
        dns_summary = f"[{packet_counter}] ({timestamp:.2f}) DNS Queries: {' '.join(q.qname.decode() for q in packet[DNS].qd)}" if \
            packet[DNS].qd else "DNS Queries: No Queries"
        output_callback(Text(dns_summary, style=DEFAULT_COLORS['DNS']))

    # DHCP Layer Parsing
    if packet.haslayer(DHCP):
        packet_counter += 1
        packet_counts['DHCP'] += 1
        dhcp_summary = f"[{packet_counter}] ({timestamp:.2f}) DHCP: {packet[DHCP].options}"
        output_callback(Text(dhcp_summary, style=DEFAULT_COLORS['DHCP']))

    # HTTP Layer Parsing
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        packet_counter += 1
        packet_counts['HTTP'] += 1
        http_layer = packet[HTTPRequest] if packet.haslayer(HTTPRequest) else packet[HTTPResponse]
        http_summary = f"[{packet_counter}] ({timestamp:.2f}) HTTP: {http_layer.Method.decode()} {http_layer.Path.decode()}"
        output_callback(Text(http_summary, style=DEFAULT_COLORS['HTTP']))

    # NTP Layer Parsing
    if packet.haslayer(NTP):
        packet_counter += 1
        packet_counts['NTP'] += 1
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


def reset_packet_counts():
    global packet_counts
    for key in packet_counts.keys():
        packet_counts[key] = 0  # Resets the packet protocol counts
