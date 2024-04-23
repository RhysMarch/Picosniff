# cli_handler.py
import time
from scapy.interfaces import IFACES
from packet_parser import parse_packet, reset_packet_counter, reset_packet_counts
from packet_sniffer import start_sniffing


async def handle_command(self, event):
    input_text = event.value.strip()
    command, *args = input_text.split()
    if command == "sniff" and args:
        iface_index = int(args[0])
        if 0 < iface_index <= len(IFACES):
            iface_name = IFACES[list(IFACES.keys())[iface_index - 1]].name
            self.output_area.clear()  # Clears the output area
            self.output_area.write(f"Sniffing on interface {iface_name}...\n")
            self.sniffing_active = True
            reset_packet_counts()  # Reset the packet count table
            reset_packet_counter()  # Reset the counter each time sniffing starts (for packet indexes)
            start_time = time.time()  # Reset the timestamp next to packets
            start_sniffing(iface_name, lambda packet: parse_packet(packet, self.output_area.write, start_time),
                           lambda: self.sniffing_active)
        else:
            self.output_area.write("Invalid interface index\n")
    elif command == "stop":
        self.sniffing_active = False
        self.output_area.write("Sniffing stopped\n")
    elif command == "clear":
        self.output_area.clear()
    elif command == "exit":
        self.exit()  # Call the Textual app's exit method
    else:
        self.output_area.write(f"Unknown or incomplete command: '{input_text}'.\n")
    self.input_field.value = ""
