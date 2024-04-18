"""
This script, Picosniff.py, serves as the main entry point for the Picosniff application. It initializes
and runs the packet sniffing and CLI handling functionalities.

Functions:
- picosniff_ascii(): Prints the Picosniff ASCII art logo.
- main(): Initializes the PacketSniffer and CLIHandler classes and handles the main application loop.

The script is intended to be run directly from the command line and interacts with the user to manage
packet sniffing operations.
"""

from packet_sniffer import PacketSniffer
from cli_handler import CLIHandler
from utils import picosniff_ascii


def main():
    restart = True
    while restart:
        picosniff_ascii()
        packet_sniffer = PacketSniffer()
        cli_handler = CLIHandler(packet_sniffer)
        restart = cli_handler.run_cli()


if __name__ == '__main__':
    main()
