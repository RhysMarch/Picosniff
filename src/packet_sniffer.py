"""
This module, packet_sniffer.py, contains the PacketSniffer class which handles the identification,
selection, and sniffing of network interfaces using Scapy.

Classes:
- PacketSniffer: Handles network interface management and packet capturing. It also dispatches packets
  to the packet parser for further processing.

The PacketSniffer class is integral to the operation of the Picosniff application, facilitating the
capture of network traffic for analysis.
"""

from scapy.all import *
from packet_parser import parse_packet, report_packet_counts
from settings import INTERFACE_DESCRIPTIONS


class PacketSniffer:
    def __init__(self):
        self.interfaces = self.display_interfaces()

    def display_interfaces(self):
        interfaces_dict = {}
        for index, (key, iface) in enumerate(sorted(IFACES.data.items(), key=lambda x: x[1].name), start=1):
            readable_name = iface.name
            description = iface.description or 'No description available'
            for prefix, readable in INTERFACE_DESCRIPTIONS.items():
                if readable_name.startswith(prefix):
                    description = readable
                    break
            interfaces_dict[index] = readable_name
            print(f"{index}: {readable_name} ({description})")
        return interfaces_dict

    def choose_interface_and_sniff(self, interface_number=None):
        if interface_number is None:
            choice = input("\nSelect an Interface (number): ")
        else:
            choice = interface_number

        try:
            selected_index = int(choice)
            if selected_index in self.interfaces:
                selected_key = self.interfaces[selected_index]
                print(f"Sniffing on interface: {selected_key}")
                sniff(iface=selected_key, prn=self.process_packet, store=False)
                report_packet_counts()  # Report the final counts once sniffing is done
            else:
                print("Invalid interface. Please enter a valid number.")
        except (ValueError, IndexError):
            print("\nInvalid input.")
        except KeyboardInterrupt:
            print("\nStopped sniffing.")
            report_packet_counts()  # Report the final counts once sniffing is done

    def process_packet(self, packet):
        parse_packet(packet)