from collections import defaultdict, deque
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, IP
import time


class AttackDetector:
    def __init__(self):
        self.arp_map = defaultdict(set)
        self.syn_events = defaultdict(deque)
        self.time_window = 1  # Default time window in seconds
        self.syn_threshold_multiplier = 1.7  # This needs fine-tuning depending on the network
        self.baseline_syn_rate = 1
        self.ewma_alpha = 0.2
        self.decay_factor = 0.1  # Introduce a decay factor

    def detect_syn_flood(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
            current_time = time.time()
            ip = packet[IP].src
            self.syn_events[ip].append(current_time)

            # Maintain SYN event history and clean up expired events
            while self.syn_events[ip] and current_time - self.syn_events[ip][0] > self.time_window:
                self.syn_events[ip].popleft()

            # Calculate the current SYN rate
            syn_rate = len(self.syn_events[ip]) / self.time_window

            # Update the baseline SYN rate using EWMA (with decay)
            self.baseline_syn_rate *= (1 - self.decay_factor)  # Apply decay
            self.baseline_syn_rate = (self.ewma_alpha * syn_rate) + ((1 - self.ewma_alpha) * self.baseline_syn_rate)

            # Calculate the dynamic threshold
            current_threshold = self.baseline_syn_rate * self.syn_threshold_multiplier

            if syn_rate >= current_threshold:
                return f"SYN Flood Caution: High SYN rate from {ip} ({syn_rate:.2f} SYNs/sec)"
        return None

    def detect_attacks(self, packet, start_time):
        syn_message = self.detect_syn_flood(packet)
        if syn_message:
            relative_time = time.time() - start_time
            message = syn_message
            return f"[{relative_time:.2f}] {message}"
        return None
