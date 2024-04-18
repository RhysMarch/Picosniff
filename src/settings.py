"""
This module, settings.py, manages configuration settings for the Picosniff application such as default
colors for packet types and payload sizes.

Functions:
- update_payload_size(size): Updates the default payload size for packet visualization.
- update_color(packet_type, color): Updates the color configuration for a given packet type.
- get_color(packet_type): Retrieves the color configuration for a given packet type.

This module centralizes configuration settings, making them easily accessible and modifiable throughout the application.
"""

# Default payload size for packet visualization
DEFAULT_PAYLOAD_SIZE = 100

# Default colors for packet types
DEFAULT_COLORS = {
    'IP': 'bright_yellow',
    'TCP': 'green1',
    'UDP': 'bright_magenta',
    'DNS': 'bright_cyan',
    'DHCP': 'bright_green',
    'HTTP': 'bright_purple',
    'NTP': 'bright_orange'
}

# Interface descriptions for network interfaces
INTERFACE_DESCRIPTIONS = {
    'lo0': 'Loopback Interface',
    'en': 'Ethernet/Wi-Fi Interface',
    'p2p': 'Peer-to-peer Interface',
    'awdl': 'Apple Wireless Direct Link',
    'bridge': 'Bridge Interface',
    'gif': 'Generic Tunnel Interface',
    'stf': 'IPv6 to IPv4 Tunnel Interface',
    'utun': 'VPN Interface',
    'enx': 'USB Ethernet Interface',
    'ap': 'Wi-Fi Access Point Interface',
    'llw': 'Low Latency Interface',
    'vlan': 'Virtual LAN Interface',
}

def update_payload_size(size):
    """Update the default payload size for packet visualization."""
    global DEFAULT_PAYLOAD_SIZE
    if size > 0:
        DEFAULT_PAYLOAD_SIZE = size
    else:
        raise ValueError("Payload size must be greater than zero.")


def update_color(packet_type, color):
    """Update the color setting for a specific packet type."""
    if packet_type in DEFAULT_COLORS:
        DEFAULT_COLORS[packet_type] = color
    else:
        raise ValueError(f"No color setting found for packet type {packet_type}")


def get_color(packet_type):
    """Retrieve the color setting for a specific packet type."""
    return DEFAULT_COLORS.get(packet_type, "white")  # Default to white if type not found
