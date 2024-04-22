# cli_handler.py
from scapy.interfaces import IFACES
from packet_parser import parse_packet
from packet_sniffer import start_sniffing


async def handle_command(self, event):
    input_text = event.value.strip()
    command, *args = input_text.split()
    if command == "sniff" and args:
        iface_index = int(args[0])
        if 0 < iface_index <= len(IFACES):
            iface_name = IFACES[list(IFACES.keys())[iface_index - 1]].name
            self.output_area.write(f"Sniffing on interface {iface_name}...\n")
            self.sniffing_active = True
            start_sniffing(iface_name, lambda packet: parse_packet(packet, self.output_area.write),
                           lambda: self.sniffing_active)
        else:
            self.output_area.write("Invalid interface index\n")
    elif command == "stop":
        self.sniffing_active = False
        self.output_area.write("Sniffing stopped\n")
    elif command == "clear":
        self.output_area.clear()
    else:
        self.output_area.write(f"Unknown or incomplete command: '{input_text}'.\n")
    self.input_field.value = ""
