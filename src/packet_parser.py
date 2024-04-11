from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.ntp import NTP
from scapy.utils import hexdump
from rich.console import Console

console = Console()


def parse_packet(packet):
    payload_size = 200

    def print_payload(layer, payload, color):
        if payload:
            payload_data = bytes(payload)
            hexdump_output = hexdump(payload_data[:payload_size], dump=True)
            console.print(f"[{color}]{hexdump_output}[/{color}]")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        color = "bright_yellow"
        console.print(f"[{color}]IP: {ip_layer.src} -> {ip_layer.dst}[/{color}]")
        print_payload(ip_layer, ip_layer.payload, color)

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        color = "green1"
        console.print(f"[{color}]TCP: {tcp_layer.sport} -> {tcp_layer.dport}[/{color}]")
        print_payload(tcp_layer, tcp_layer.payload, color)

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        color = "bright_magenta"
        console.print(f"[{color}]UDP: {udp_layer.sport} -> {udp_layer.dport}[/{color}]")
        print_payload(udp_layer, udp_layer.payload, color)

    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        color = "bright_cyan"
        console.print(f"[{color}]DNS: {dns_layer.summary()}[/{color}]", style=color)

    if packet.haslayer(DHCP):
        dhcp_layer = packet[DHCP]
        color = "bright_green"
        console.print(f"[{color}]DHCP: {dhcp_layer.summary()}[/{color}]", style=color)

    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        http_layer = packet[HTTP]
        color = "bright_purple"
        console.print(f"[{color}]HTTP: {http_layer.summary()}[/{color}]", style=color)

    if packet.haslayer(NTP):
        ntp_layer = packet[NTP]
        color = "bright_orange"
        console.print(f"[{color}]NTP: {ntp_layer.summary()}[/{color}]", style=color)