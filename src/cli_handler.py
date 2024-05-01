"""
cli_handler.py

This module defines the command handling logic for a Textual-based network packet sniffing application.
It interprets user inputs and executes actions such as starting or stopping packet sniffing on specified network interfaces,
clearing the display, or exiting the application.

Functions:
- handle_command(self, event): Parses and executes commands received through a textual input widget.

Responsibilities:
- Start and stop packet sniffing on specified network interfaces.
- Reset packet statistics and counters when sniffing is initiated.
- Provide real-time feedback to the user by updating the application's output area.
- Validate user commands and provide feedback for unrecognised or malformed commands.

The `handle_command` function is designed to be a method of a class that represents the application's main interface,
expecting that the class instance (`self`) will have attributes like `output_area` for logging messages to the user,
and `sniffing_active` to track the state of packet sniffing.

Usage:
This module is used within a Textual application where commands are issued through an input field. The `handle_command`
function is bound to events triggered by submitting text in this field.

Example:
Assuming an integration with a Textual App class:

    @on(Input.Submitted)
    async def handle_command_wrapper(self, event):
        await handle_command(self, event)

This function will interpret commands such as 'sniff', 'stop', 'clear', and 'exit', executing corresponding actions.

Dependencies:
- scapy.interfaces.IFACES: Used to validate and resolve network interface specifications from user commands.
- packet_parser: Utilises functions to parse packets and manage packet counters.
- packet_sniffer: Calls functionality to begin sniffing packets on designated interfaces.
"""
import time
from scapy.interfaces import IFACES
from packet_parser import parser
from packet_sniffer import start_sniffing
from visualisation import PacketFlowPlot


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
            self.app.query_one(PacketFlowPlot).start_tracking()  # Start time tracking on the plot
            parser.reset_packet_counts()  # Reset using the parser instance
            parser.reset_packet_counter()
            parser.start_time = time.time()  # Reset the timestamp next to packets
            start_sniffing(iface_name, lambda packet: parser.parse_packet(packet, self.output_area.write),
                           lambda: self.sniffing_active)

            def check_for_no_packets():
                if parser.packet_counter == 0:
                    self.output_area.write(
                        "No packets captured. Consider running with administrator/root privileges.\n")
            self.set_timer(5, check_for_no_packets)

        else:
            self.output_area.write("Invalid interface index\n")
    elif command == "stop":
        self.sniffing_active = False
        self.output_area.write("Sniffing stopped\n")
        self.app.query_one(PacketFlowPlot).reset()  # Reset the plot
    elif command == "clear":
        self.output_area.clear()
    elif command == "exit":
        self.exit()  # Call the Textual app's exit method
    else:
        self.output_area.write(f"Unknown or incomplete command: '{input_text}'.\n")
    self.input_field.value = ""
