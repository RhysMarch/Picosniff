import textwrap
from collections import defaultdict, deque
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, IP
import time


class AttackDetector:
    def __init__(self):
        self.arp_map = defaultdict(list)
        self.syn_events = defaultdict(lambda: deque(maxlen=20))
        self.syn_threshold = 20  # SYNs per second threshold
        self.time_window = 10  # Time window for SYN rate calculation

    def detect_arp_spoofing(self, packet):
        """Detects ARP Spoofing by tracking unique MAC-IP associations."""
        if packet.haslayer(ARP):
            if packet[ARP].psrc not in self.arp_map[packet[ARP].hwsrc]:
                self.arp_map[packet[ARP].hwsrc].append(packet[ARP].psrc)
            if len(self.arp_map[packet[ARP].hwsrc]) > 1:
                return self.wrap_text(
                    f"ARP Spoofing Warning: Multiple IPs ({', '.join(self.arp_map[packet[ARP].hwsrc])}) associated with MAC {packet[ARP].hwsrc}")
        return None

    def detect_syn_flood(self, packet):
        """Detects SYN Flood by monitoring SYN rates over time."""
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
            current_time = time.time()
            self.syn_events[packet[IP].src].append(current_time)
            while self.syn_events[packet[IP].src] and current_time - self.syn_events[packet[IP].src][
                0] > self.time_window:
                self.syn_events[packet[IP].src].popleft()
            syn_rate = len(self.syn_events[packet[IP].src]) / self.time_window
            if syn_rate >= self.syn_threshold:
                return self.wrap_text(
                    f"SYN Flood Warning: High SYN rate detected from {packet[IP].src} ({syn_rate:.2f} SYNs/sec)")
        return None

    def detect_attacks(self, packet, start_time):
        """Detects and formats attack messages with timestamp and wrapping."""
        current_time = time.time()
        relative_time = current_time - start_time
        arp_message = self.detect_arp_spoofing(packet)
        syn_message = self.detect_syn_flood(packet)
        if arp_message:
            return f"[{relative_time:.2f}] {arp_message}"
        if syn_message:
            return f"[{relative_time:.2f}] {syn_message}"
        return None

    @staticmethod
    def wrap_text(message, width=60):
        """Wraps text to a specified width."""
        wrapper = textwrap.TextWrapper(width=width, break_long_words=False, replace_whitespace=False)
        return '\n'.join(wrapper.wrap(message))
