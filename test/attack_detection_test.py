"""
attack_detection_test.py

This module provides functions to simulate network attacks for testing purposes. The attacks are designed to trigger alerts in the main application's attack detection system.

Functions:
- simulate_syn_flood(interface, victim_ip=None, target_port=80, count=250, packet_size=1024):
    - Simulates a SYN flood attack by sending TCP SYN packets to the specified victim IP and port.
    - If no victim IP is provided, the local IP address is used as the target.
    - Parameters:
        - interface: The network interface to use for sending the packets.
        - victim_ip: The IP address of the target system (optional).
        - target_port: The port to target on the victim system (default: 80).
        - count: The number of SYN packets to send (default: 250).
        - packet_size: The size of each SYN packet in bytes (default: 1024).
- simulate_dns_flood(interface, victim_ip=None, target_port=53, count=500):
    - Simulates a DNS query flood attack by sending numerous DNS queries to the specified victim IP and port.
    - If no victim IP is provided, the local IP address is used as the target.
    - Parameters:
        - interface: The network interface to use for sending the packets.
        - victim_ip: The IP address of the target system (optional).
        - target_port: The port to target on the victim system (default: 53).
        - count: The number of DNS queries to send (default: 500).

Dependencies:
- scapy: Used for constructing and sending packets.
- visualisation: Used for getting the local IP address if no victim IP is specified.

Usage:
- These functions are primarily intended for testing the attack detection capabilities of the main application.
- They can be called directly from a script or through the "test" command in the application's interface.
"""
from random import randint
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort, RandString
from visualisation import get_local_ip


def simulate_syn_flood(interface, victim_ip=None, target_port=80, count=250, packet_size=1024):
    if not victim_ip:
        victim_ip = get_local_ip()

    if victim_ip == get_local_ip():  # Check if targeting self
        ip_layer = IP(dst=victim_ip, src="127.0.0.1")  # Force source IP
    else:
        ip_layer = IP(dst=victim_ip)

    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw_payload = Raw(b"SYN_Flood_" + b"X" * (packet_size - len(b"SYN_Flood_")))

    packet = ip_layer / tcp_layer / raw_payload

    for _ in range(count):
        send(packet, iface=interface, verbose=0)


def simulate_dns_flood(interface, victim_ip=None, target_port=53, count=500):
    if not victim_ip:
        victim_ip = get_local_ip()

    if victim_ip == get_local_ip():  # Check if targeting self
        ip_layer = IP(dst=victim_ip, src="127.0.0.1")  # Force source IP
    else:
        ip_layer = IP(dst=victim_ip)

    udp_layer = UDP(sport=randint(1024, 65535), dport=target_port)

    domain = "example.com"
    for _ in range(count):
        subdomain = RandString(12).decode()
        dns_layer = DNS(rd=1, qd=DNSQR(qname=subdomain + '.' + domain))
        packet = ip_layer / udp_layer / dns_layer
        send(packet, iface=interface, verbose=0)
