"""
Module: packet_sniffer.py

Provides functions for network packet sniffing using Scapy.

Functions:
  start_sniffing(iface_name, packet_handler, sniffing_active_callback):
    Starts a background sniffing thread to capture packets.
"""
from scapy.all import sniff
import threading


def start_sniffing(iface_name, packet_handler, sniffing_active_callback):
    def sniff_thread():
        sniff(iface=iface_name, prn=packet_handler, stop_filter=lambda x: not sniffing_active_callback())

    threading.Thread(target=sniff_thread, daemon=True).start()
