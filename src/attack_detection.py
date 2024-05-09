from collections import defaultdict, deque
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, IP
import time


class AttackDetector:
    def __init__(self):
        self.arp_map = defaultdict(set)
        self.event_history = {
            'syn': defaultdict(deque),
            'dns': defaultdict(deque)
        }
        self.time_window = 1

        # Adjustable parameters:
        self.threshold_multipliers = {'syn': 2, 'dns': 2}
        self.baseline_rates = {'syn': 1.2, 'dns': 1.5}
        self.ewma_alpha = 0.2
        self.decay_factor = 0.3

    def _detect_flood(self, packet, event_type):
        if event_type == 'syn' and packet.haslayer(TCP) and packet[TCP].flags & 0x02:
            source = packet[IP].src
        elif event_type == 'dns' and packet.haslayer(DNS) and packet[DNS].qr == 0:
            source = packet[IP].src
        else:
            return None

        current_time = time.time()
        self.event_history[event_type][source].append(current_time)
        self._cleanup_events(event_type)  # Cleanup old events

        rate = len(self.event_history[event_type][source]) / self.time_window

        self.baseline_rates[event_type] *= (1 - self.decay_factor)
        self.baseline_rates[event_type] = (self.ewma_alpha * rate) + ((1 - self.ewma_alpha) * self.baseline_rates[event_type])

        threshold = self.baseline_rates[event_type] * self.threshold_multipliers[event_type]
        if rate >= threshold:
            fmt_str = f"{event_type.upper()} Flood Caution: High {event_type} rate from {{}} ({{:.2f}} {event_type}/sec)"
            return fmt_str.format(source, rate)
        return None

    def _cleanup_events(self, event_type):
        """Removes expired events from the event history"""
        current_time = time.time()
        for ip, events in self.event_history[event_type].items():
            while events and current_time - events[0] > self.time_window:
                events.popleft()

    def detect_attacks(self, packet, start_time):
        for event_type in ['syn', 'dns']:
            message = self._detect_flood(packet, event_type)
            if message:
                relative_time = time.time() - start_time
                return f"[{relative_time:.2f}] {message}"
        return None
