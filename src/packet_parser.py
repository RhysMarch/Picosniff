"""
This file, packet_parser.py, contains functions and utilities for parsing packets captured by the sniffer function.

The file supports parsing various types of network protocols including IP, TCP, UDP, DNS, DHCP, HTTP, and NTP.
Each packet type is handled by a specific function that extracts and prints relevant information using a
standardized format provided by the visualisation module.

Functions:
- parse_packet(packet): The main entry point for parsing packets. It dispatches to specific parsing
  functions based on the packet type.

Dependencies:
- scapy.all: Used for capturing and dissecting packets.
- visualisation.py: Used for formatting and coloring output.
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.ntp import NTP
from scapy.utils import hexdump
from visualisation import print_colored
from settings import DEFAULT_PAYLOAD_SIZE


def parse_packet(packet):
    payload_size = DEFAULT_PAYLOAD_SIZE

    def print_payload(layer, packet_type):
        if layer.payload:
            payload_data = bytes(layer.payload)
            hexdump_output = hexdump(payload_data[:payload_size], dump=True)
            print_colored(hexdump_output, packet_type)

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print_colored(f"IP: {ip_layer.src} -> {ip_layer.dst}", 'IP')
        print_payload(ip_layer, 'IP')

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print_colored(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport}", 'TCP')
        print_payload(tcp_layer, 'TCP')

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print_colored(f"UDP: {udp_layer.sport} -> {udp_layer.dport}", 'UDP')
        print_payload(udp_layer, 'UDP')

    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        summary = dns_layer.summary()
        print_colored(f"DNS: {summary}", 'DNS')
        print_payload(dns_layer, 'DNS')

    if packet.haslayer(DHCP):
        dhcp_layer = packet[DHCP]
        summary = dhcp_layer.summary()
        print_colored(f"DHCP: {summary}", 'DHCP')
        print_payload(dhcp_layer, 'DHCP')

    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        http_layer = packet[HTTP]
        summary = http_layer.summary()
        print_colored(f"HTTP: {summary}", 'HTTP')
        print_payload(http_layer, 'HTTP')

    if packet.haslayer(NTP):
        ntp_layer = packet[NTP]
        summary = ntp_layer.summary()
        print_colored(f"NTP: {summary}", 'NTP')
        print_payload(ntp_layer, 'NTP')

