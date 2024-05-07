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

Dependencies:
- Scapy: Used for packet capture and analysis.
- Rich: Used for formatting and displaying text in a more readable and visually appealing format.
- Python Standard Library: Uses modules like time for timestamping.

Usage:
This module is intended to be used where packet capture data needs to be parsed, formatted, and displayed in real-time. It integrates directly with systems
that capture packets using Scapy and can output data either to the console or to a UI via provided callback functions.

Example:
To use parse_packet function, ensure you provide a packet object received from Scapy, a callback function to handle strings of formatted packet summaries,
and a start time for relative timing information.
"""
import textwrap
from collections import defaultdict
from scapy.all import Raw, hexdump
from settings import DEFAULT_PAYLOAD_SIZE, DEFAULT_COLORS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.ntp import NTP
from rich.text import Text
import time


class PacketParser:
    def __init__(self):
        self.start_time = time.time()  # Initialise upon object creation
        self.packet_counter = 0
        self.ip_distribution = defaultdict(int)
        self.packet_counts = {
            'IP': 0,
            'TCP': 0,
            'UDP': 0,
            'DNS': 0,
            'DHCP': 0,
            'HTTP': 0,
            'NTP': 0
        }

    def parse_packet(self, packet, output_callback):
        try:
            current_time = time.time()
            if self.start_time is None or current_time < self.start_time:
                self.start_time = current_time

            timestamp = current_time - self.start_time

            if packet.haslayer(IP):
                self._handle_ip_layer(packet, output_callback, timestamp)
            if packet.haslayer(TCP):
                self._handle_tcp_layer(packet, output_callback, timestamp)
            if packet.haslayer(UDP):
                self._handle_udp_layer(packet, output_callback, timestamp)
            if packet.haslayer(DNS):
                self._handle_dns_layer(packet, output_callback, timestamp)
            if packet.haslayer(DHCP):
                self._handle_dhcp_layer(packet, output_callback, timestamp)
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                self._handle_http_layer(packet, output_callback, timestamp)
            if packet.haslayer(NTP):
                self._handle_ntp_layer(packet, output_callback, timestamp)

        except Exception as e:
            output_callback(Text(f"Error processing packet: {e}", style="bold red"))

    def _handle_ip_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['IP'] += 1
        self.ip_distribution[packet[IP].src] += 1
        self.ip_distribution[packet[IP].dst] += 1
        ip_summary = f"[{self.packet_counter}] ({timestamp:.2f}) IP: {packet[IP].src} -> {packet[IP].dst}"
        output_callback(Text(ip_summary, style=DEFAULT_COLORS['IP']))
        handle_payload(packet, output_callback, 'IP')

    def _handle_tcp_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['TCP'] += 1
        tcp_summary = f"[{self.packet_counter}] ({timestamp:.2f}) TCP: {packet[TCP].sport} -> {packet[TCP].dport}"
        output_callback(Text(tcp_summary, style=DEFAULT_COLORS['TCP']))
        handle_payload(packet, output_callback, 'TCP')

    def _handle_udp_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['UDP'] += 1
        udp_summary = f"[{self.packet_counter}] ({timestamp:.2f}) UDP: {packet[UDP].sport} -> {packet[UDP].dport}"
        output_callback(Text(udp_summary, style=DEFAULT_COLORS['UDP']))
        handle_payload(packet, output_callback, 'UDP')

    def _handle_dns_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['DNS'] += 1
        dns_summary = f"[{self.packet_counter}] ({timestamp:.2f}) DNS Queries: {' '.join(q.qname.decode() for q in packet[DNS].qd)}" if \
            packet[DNS].qd else "DNS Queries: No Queries"
        output_callback(Text(dns_summary, style=DEFAULT_COLORS['DNS']))
        handle_payload(packet, output_callback, 'DNS')

    def _handle_dhcp_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['DHCP'] += 1
        dhcp_summary = f"[{self.packet_counter}] ({timestamp:.2f}) DHCP: {packet[DHCP].options}"
        output_callback(Text(dhcp_summary, style=DEFAULT_COLORS['DHCP']))
        handle_payload(packet, output_callback, 'DHCP')

    def _handle_http_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['HTTP'] += 1
        http_layer = packet[HTTPRequest] if packet.haslayer(HTTPRequest) else packet[HTTPResponse]
        http_summary = f"[{self.packet_counter}] ({timestamp:.2f}) HTTP: {http_layer.Method.decode()} {http_layer.Path.decode()}"
        output_callback(Text(http_summary, style=DEFAULT_COLORS['HTTP']))
        handle_payload(packet, output_callback, 'HTTP')

    def _handle_ntp_layer(self, packet, output_callback, timestamp):
        self.packet_counter += 1
        self.packet_counts['NTP'] += 1
        ntp_summary = f"[{self.packet_counter}] ({timestamp:.2f}) NTP Version: {packet[NTP].version}"
        output_callback(Text(ntp_summary, style=DEFAULT_COLORS['NTP']))
        handle_payload(packet, output_callback, 'NTP')

    @staticmethod
    def reset_packet_counts():
        for key in parser.packet_counts.keys():
            parser.packet_counts[key] = 0

    @staticmethod
    def reset_packet_counter():
        parser.packet_counter = 0


def handle_payload(packet, output_callback, protocol):
    if packet.haslayer(Raw):
        payload = packet[Raw].load[:DEFAULT_PAYLOAD_SIZE]
        payload_hexdump = hexdump(payload, dump=True)
        output_callback(Text(payload_hexdump, style=DEFAULT_COLORS[protocol]))
    else:
        # Custom handling for structured data per protocol
        if protocol == 'DNS':
            dns_info = parse_dns_details(packet[DNS])
            output_callback(Text(dns_info, style=DEFAULT_COLORS[protocol]))
        elif protocol == 'DHCP':
            dhcp_info = parse_dhcp_details(packet[DHCP])
            output_callback(Text(dhcp_info, style=DEFAULT_COLORS[protocol]))
        elif protocol == 'HTTP':
            http_info = parse_http_details(packet)
            output_callback(Text(http_info, style=DEFAULT_COLORS[protocol]))
        elif protocol == 'NTP':
            ntp_info = parse_ntp_details(packet[NTP])
            output_callback(Text(ntp_info, style=DEFAULT_COLORS[protocol]))


def parse_dns_details(dns_layer):
    wrapper = textwrap.TextWrapper(width=70, subsequent_indent='  ')
    dns_details = "DNS Queries and Answers:\n"
    if dns_layer.qr == 0:  # Query
        dns_details += "Questions:\n"
        for q in dns_layer.qd:
            question = f"  - {q.qname.decode() if hasattr(q.qname, 'decode') else q.qname}"
            dns_details += '\n'.join(wrapper.wrap(question)) + '\n'
    else:  # Response
        dns_details += "Answers:\n"
        for a in dns_layer.an:
            answer = f"  - {a.rrname.decode() if hasattr(a.rrname, 'decode') else a.rrname} -> {a.rdata}"
            dns_details += '\n'.join(wrapper.wrap(answer)) + '\n'
    if dns_details.endswith('\n'):
        dns_details = dns_details[:-1]  # Remove the last newline if present
    return dns_details


def parse_dhcp_details(dhcp_layer):
    wrapper = textwrap.TextWrapper(width=70, subsequent_indent='  ')
    dhcp_details = "DHCP Options:\n"
    for option in dhcp_layer.options:
        if option[0] == 'end':
            break
        option_detail = f"  - {option[0]}: {option[1]}"
        dhcp_details += '\n'.join(wrapper.wrap(option_detail)) + '\n'
    if dhcp_details.endswith('\n'):
        dhcp_details = dhcp_details[:-1]  # Remove the last newline if present
    return dhcp_details


def parse_http_details(http_packet):
    wrapper = textwrap.TextWrapper(width=70, subsequent_indent='  ')
    http_details = ""
    if http_packet.haslayer(HTTPRequest):
        request = http_packet[HTTPRequest]
        http_details += "HTTP Request:\n"
        details = f"  Method: {request.Method.decode()}\n  Path: {request.Path.decode()}\n  Host: {request.Host.decode()}\n"
        http_details += '\n'.join(wrapper.wrap(details)) + '\n'
    if http_packet.haslayer(HTTPResponse):
        response = http_packet[HTTPResponse]
        if http_details:
            http_details += '\n'  # Only add a newline if there's already request info
        http_details += "HTTP Response:\n"
        details = f"  Status Code: {response.Status_Code.decode()}\n  Reason: {response.Reason_Phrase.decode()}\n"
        http_details += '\n'.join(wrapper.wrap(details))
    if http_details.endswith('\n'):
        http_details = http_details[:-1]  # Remove the last newline if present
    return http_details


def parse_ntp_details(ntp_layer):
    wrapper = textwrap.TextWrapper(width=70, subsequent_indent='  ')
    ntp_details = "NTP Message:\n"
    details = f"  Leap Indicator: {ntp_layer.leap}\n  Version: {ntp_layer.version}\n  Mode: {ntp_layer.mode}\n"
    ntp_details += '\n'.join(wrapper.wrap(details))
    if ntp_details.endswith('\n'):
        ntp_details = ntp_details[:-1]  # Remove the last newline if present
    return ntp_details


parser = PacketParser()
