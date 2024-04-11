from scapy.all import *
from packet_parser import parse_packet


class PacketSniffer:
    def __init__(self):
        self.interfaces = self.display_interfaces()

    def display_interfaces(self):
        interfaces_dict = {}
        interface_descriptions = {
            'lo0': 'Loopback Interface',
            'en': 'Ethernet/Wi-Fi Interface',
            'p2p': 'Peer-to-peer Interface',
            'awdl': 'Apple Wireless Direct Link',
            'bridge': 'Bridge Interface',
            'gif': 'Generic Tunnel Interface',
            'stf': 'IPv6 to IPv4 Tunnel Interface',
            'utun': 'VPN Interface',
            'enx': 'USB Ethernet Interface',
            'ap': 'Wi-Fi Access Point Interface',
            'llw': 'Low Latency Interface',
            'vlan': 'Virtual LAN Interface',
        }

        for index, (key, iface) in enumerate(sorted(IFACES.data.items(), key=lambda x: x[1].name), start=1):
            readable_name = iface.name
            description = iface.description or 'No description available'
            # Find a more readable name if it matches known interfaces
            for prefix, readable in interface_descriptions.items():
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
            else:
                print("Invalid interface. Please enter a valid number.")
        except (ValueError, IndexError):
            print("\nInvalid input.")
        except KeyboardInterrupt:
            print("\nStopped sniffing.")

    def process_packet(self, packet):
        parse_packet(packet)