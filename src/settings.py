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


def update_payload_size(size):
    """Update the default payload size for packet visualization."""
    global DEFAULT_PAYLOAD_SIZE
    if size > 0:
        DEFAULT_PAYLOAD_SIZE = size
    else:
        raise ValueError("Payload size must be greater than zero.")
