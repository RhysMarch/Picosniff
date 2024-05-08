"""
tui_handler.py

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

Dependencies:
- scapy.interfaces.IFACES: Used to validate and resolve network interface specifications from user commands.
- packet_parser: Utilises functions to parse packets and manage packet counters.
- packet_sniffer: Calls functionality to begin sniffing packets on designated interfaces.
"""
import gc
import time
from scapy.interfaces import IFACES
from packet_parser import parser
from packet_sniffer import start_sniffing
from visualisation import PacketFlowPlot, IPDistributionTable


async def handle_command(handler, event):

    input_text = event.value.strip()
    if not input_text:
        # If there's no input, just return without doing anything
        return

    command, *args = input_text.split()

    command_actions = {
        'sniff': handler.handle_sniff,
        'stop': handler.handle_stop,
        'clear': handler.handle_clear,
        'exit': handler.handle_exit,
        'unknown': handler.handle_unknown_command
    }

    func = command_actions.get(command, command_actions['unknown'])
    await func(args)


class CommandHandler:
    def __init__(self, app):
        self.app = app

    async def handle_sniff(self, args):
        if not args:
            self.app.output_area.write("No interface specified.\n")
            return

        iface_index = int(args[0])
        if 0 < iface_index <= len(IFACES):
            iface_name = IFACES[list(IFACES.keys())[iface_index - 1]].name
            self.start_sniffing_on_interface(iface_name)
        else:
            self.app.output_area.write("Invalid interface index\n")

    async def handle_stop(self, args):
        self.app.sniffing_active = False
        self.app.query_one(PacketFlowPlot).reset()  # Reset the plot

    async def handle_clear(self, args):
        self.app.output_area.clear()
        self.show_interfaces()  # Show top left interface once 'clear'
        gc.collect()

    async def handle_exit(self, args):
        self.app.exit()  # Exit the application

    async def handle_unknown_command(self, args):
        self.app.output_area.write(f"Unknown or incomplete command")

    def show_attack_pane(self):
        attack_pane = self.app.query_one("#bottom-left-attack-pane")
        attack_pane.display = True

    def hide_interfaces(self) -> None:
        top_left_pane = self.app.query_one("#top-left-pane")
        top_left_pane.display = not top_left_pane.display

    def show_interfaces(self) -> None:
        top_left_pane = self.app.query_one("#top-left-pane")
        top_left_pane.display = True

    def start_sniffing_on_interface(self, iface_name):
        self.app.output_area.clear()
        self.hide_interfaces()  # Hide top left pane when sniffing starts
        self.app.output_area.write(f"Sniffing on interface {iface_name}...\n")
        self.app.sniffing_active = True
        self.app.query_one(PacketFlowPlot).start_tracking()
        self.app.query_one(IPDistributionTable).reset()
        parser.reset_packet_counts()
        parser.reset_packet_counter()
        parser.start_time = time.time()
        start_sniffing(iface_name, lambda packet: parser.parse_packet(packet, self.app.output_area.write),
                       lambda: self.app.sniffing_active)
        self.app.set_timer(5, self.check_for_no_packets)

    def check_for_no_packets(self):
        if parser.packet_counter == 0:
            self.app.output_area.write("No packets captured. Are you running with administrator/root privileges?\n")
