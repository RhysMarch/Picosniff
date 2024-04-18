"""
This module, visualisation.py, handles the visual representation of packet information within the Picosniff
application, utilizing the Rich library for formatted console output.

Functions:
- print_colored(text, packet_type): Prints text to the console with color settings based on packet type.

This module simplifies the task of displaying colored and formatted text output based on packet types.
"""

from rich.console import Console
from rich.table import Table
from settings import get_color
from rich.text import Text


console = Console()


def print_colored(text, packet_type):
    """Print text using a specific color."""
    color = get_color(packet_type)
    text_obj = Text(text, style=color)
    console.print(text_obj)


def display_packet_statistics(packet_counts):
    """Displays a summary table of packet counts."""
    table = Table(title=" ")
    table.add_column("Packet Type", style="cyan", no_wrap=True)
    table.add_column("Count", style="magenta")
    for packet_type, count in sorted(packet_counts.items()):
        table.add_row(packet_type, str(count))
    console.print(table)