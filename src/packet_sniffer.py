from scapy.all import *


class PacketSniffer:
    def __init__(self):
        self.choose_interface_and_sniff()

    def list_interfaces(self):

        readable_interfaces = {}
        for key, iface in IFACES.data.items():
            readable_name = iface.name
            description = iface.description
            readable_interfaces[readable_name] = description
        return readable_interfaces

    def choose_interface_and_sniff(self):
        interfaces = self.list_interfaces()

        for index, (name, desc) in enumerate(interfaces.items()):
            print(f"{index}: {name} ({desc})")

        choice = input("""\nSelect an Interface: """)
        try:
            selected_key = list(interfaces.keys())[int(choice)]
            print(f"Sniffing on interface: {selected_key}")
            sniff(iface=selected_key, prn=self.process_packet)

        except (ValueError, IndexError):
            print("Enter a valid interface number.")
        except KeyboardInterrupt:
            print("\nStopped sniffing.")

    def process_packet(self, packet):
        print(packet.summary())
