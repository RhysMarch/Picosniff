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
        self.time_window = 5  # Time window for analysis (in seconds)

        # Adjustable parameters:
        self.threshold_multipliers = {'syn': 2, 'dns': 3}  # Multipliers for dynamic thresholds
        self.baseline_rates = {'syn': 2, 'dns': 3}         # Initial baseline rates
        self.ewma_alpha = 0.2                            # Smoothing factor for EWMA
        self.decay_factor = 0.3                          # Decay factor for baseline adjustment

    def _detect_flood(self, packet, event_type):
        if event_type == 'syn' and packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # Check for SYN flag
            source = packet[IP].src
        elif event_type == 'dns' and packet.haslayer(DNS) and packet[DNS].qr == 0:      # Check for DNS query
            source = packet[IP].src
        else:
            return None

        current_time = time.time()
        self.event_history[event_type][source].append(current_time)  # Add event to history
        self._cleanup_events(event_type)                              # Remove old events

        rate = len(self.event_history[event_type][source]) / self.time_window  # Calculate event rate

        # Update baseline rate using EWMA
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
                # Parse out the rate from the message
                rate = float(message.split("(")[-1].split()[0])
                if rate >= 5.0:  # Filter out alerts below 5 events/sec
                    return f"[{relative_time:.2f}] {message}"
        return None
