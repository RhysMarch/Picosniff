"""
Module: utils.py

Provides utility functions for network interface discovery and ASCII art logo generation.

Functions:
  ascii_logo(): Returns a string containing an ASCII art representation of the Picosniff logo.

  get_interfaces_info(): Collects information about available network interfaces and formats it into a Rich Text object.
"""
import platform
from rich.text import Text
from scapy.interfaces import IFACES
from settings import INTERFACE_NAME_MAP


def ascii_logo() -> str:
    return """\
        ____  _                       _ ________
       / __ \(_)________  _________  (_) __/ __/
      / /_/ / / ___/ __ \/ ___/ __ \/ / /_/ /_  
     / ____/ / /__/ /_/ (__  ) / / / / __/ __/  
    /_/   /_/\___/\____/____/_/ /_/_/_/ /_/        
            """


def get_interfaces_info() -> Text:
    interfaces_info = Text("Available Network Interfaces:\n")
    for index, iface in enumerate(IFACES, 1):
        iface_obj = IFACES[iface]
        if platform.system() == 'Darwin':  # Check if we're on macOS
            INTERFACE_NAME_MAP.get(iface, iface)  # Use the map
        else:
            iface_name = iface_obj.name  # Try to get the name directly
            description = iface_obj.description or 'No description available'
            interfaces_info.append(f"{index}: {iface_name} ({description})\n")
    return interfaces_info
