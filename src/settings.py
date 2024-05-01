"""
This module, settings.py, manages configuration settings for the Picosniff application such as default
colors for packet types and payload sizes.

Functions:
- update_payload_size(size): Updates the default payload size for packet visualization.

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

INTERFACE_NAME_MAP = {
    'lo0': 'Loopback (localhost)',
    'en0': 'Ethernet / Wi-Fi (Primary)',
    'en1': 'Ethernet (Secondary)',
    'en2': 'Ethernet (Additional)',
    'en3': 'Ethernet (Additional)',
    'en4': 'Ethernet (Additional)',
    'en5': 'Ethernet (Additional)',
    'bridge0': 'Thunderbolt Bridge',
    'ap1': 'Access Point (Wireless)',  # Or a more accurate description if needed
    'awd10': 'Apple Wireless Direct Link',
    'llw0': 'Low-latency WLAN Interface'
}



def update_payload_size(size):
    """Update the default payload size for packet visualization."""
    global DEFAULT_PAYLOAD_SIZE
    if size > 0:
        DEFAULT_PAYLOAD_SIZE = size
    else:
        raise ValueError("Payload size must be greater than zero.")
