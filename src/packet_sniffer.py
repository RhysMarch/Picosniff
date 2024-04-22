# packet_sniffer.py
from scapy.all import sniff
import threading

def start_sniffing(iface_name, output_callback, sniffing_active_callback):
    def sniff_thread():
        sniff(iface=iface_name, prn=output_callback, stop_filter=lambda x: not sniffing_active_callback())
    threading.Thread(target=sniff_thread).start()