"""
This module, visualisation.py, handles the visual representation of packet information within the Picosniff
application, utilizing the Rich library for formatted console output.

Functions:
- print_colored(text, packet_type): Prints text to the console with color settings based on packet type.

This module simplifies the task of displaying colored and formatted text output based on packet types.
"""

from rich.console import Console
from settings import get_color

console = Console()


def print_colored(text, packet_type):
    """Print text with the color associated with the packet type using settings from settings.py."""
    color = get_color(packet_type)
    console.print(f"[{color}]{text}[/{color}]")
