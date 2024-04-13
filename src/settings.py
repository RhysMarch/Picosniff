# settings.py

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


def update_color(packet_type, color):
    """Update the color setting for a specific packet type."""
    if packet_type in DEFAULT_COLORS:
        DEFAULT_COLORS[packet_type] = color
    else:
        raise ValueError(f"No color setting found for packet type {packet_type}")


def get_color(packet_type):
    """Retrieve the color setting for a specific packet type."""
    return DEFAULT_COLORS.get(packet_type, "white")  # Default to white if type not found
