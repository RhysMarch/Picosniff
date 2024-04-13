# visualisation.py
from rich.console import Console
from settings import get_color

console = Console()


def print_colored(text, packet_type):
    """Print text with the color associated with the packet type using settings from settings.py."""
    color = get_color(packet_type)
    console.print(f"[{color}]{text}[/{color}]")
