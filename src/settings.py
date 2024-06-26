"""
This module, settings.py, manages configuration settings for the Picosniff application such as default
colors for packet types and payload sizes.

This module centralises configuration settings, making them easily accessible and modifiable throughout the application.
"""

# Default payload size for packet visualisation
DEFAULT_PAYLOAD_SIZE = 100

# Default colors for packet types
DEFAULT_COLORS = {
    'IP': 'bright_yellow',
    'TCP': 'green1',
    'UDP': 'bright_magenta',
    'DNS': 'bright_cyan',
    'DHCP': 'bright_green',
    'HTTP': 'bright_white',
    'NTP': 'bright_orange',
    'ARP': 'dark_violet'
}

MAC_INTERFACE_NAME_MAP = {
    'lo0': 'Loopback (localhost)',
    'en0': 'Ethernet / Wi-Fi (Primary)',
    'en1': 'Ethernet (Secondary)',
    'en2': 'Ethernet (Additional)',
    'en3': 'Ethernet (Additional)',
    'en4': 'Ethernet (Additional)',
    'en5': 'Ethernet (Additional)',
    'bridge0': 'Thunderbolt Bridge',
    'ap1': 'Access Point (Wireless)',
    'awd10': 'Apple Wireless Direct Link',
    'llw0': 'Low-latency WLAN Interface'
}

LINUX_INTERFACE_NAME_MAP = {
    'eth0': 'Ethernet 0',
    'wlan0': 'Wireless LAN',
    'lo': 'Localhost Loopback'
}
