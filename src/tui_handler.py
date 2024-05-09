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
import threading
import time
from rich.panel import Panel
from rich.text import Text
from scapy.interfaces import IFACES
from packet_parser import parser
from packet_sniffer import start_sniffing
from visualisation import PacketFlowPlot, IPDistributionTable, get_local_ip
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'test'))
from attack_detection_test import simulate_syn_flood, simulate_dns_flood


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
        'help': handler.handle_help,
        'exit': handler.handle_exit,
        'test': handler.handle_test,
        'unknown': handler.handle_unknown_command
    }

    func = command_actions.get(command, command_actions['unknown'])
    await func(args)


class CommandHandler:
    def __init__(self, app):
        self.app = app
        self.current_interface = None

    async def handle_sniff(self, args):
        if not args:
            self.app.output_area.write("No interface specified.\n")
            return

        iface_index = int(args[0])
        if 0 < iface_index <= len(IFACES):
            iface_name = IFACES[list(IFACES.keys())[iface_index - 1]].name
            self.current_interface = iface_name  # Store the current interface being sniffed
            self.start_sniffing_on_interface(iface_name)
        else:
            self.app.output_area.write("Invalid interface index\n")

    async def handle_stop(self, args):
        self.app.sniffing_active = False
        self.app.query_one(PacketFlowPlot).reset()  # Reset the plot

    async def handle_clear(self, args):
        self.app.output_area.clear()
        self.app.attack_output_area.clear()
        self.app.sniffing_active = False  # Clear also stops sniffing
        self.show_interfaces()  # Show top left interface once 'clear'
        self.hide_attack_pane()
        gc.collect()

    async def handle_help(self, args):
        self.app.output_area.clear()
        # Create a rich Text object for better formatting
        help_text = Text()

        # Add commands and descriptions with styles
        help_text.append("sniff <interface_index>", style="bold cyan")
        help_text.append(" : Starts packet sniffing on the specified interface.\n", style="white")

        help_text.append("stop", style="bold cyan")
        help_text.append(" : Stops packet sniffing.\n", style="white")

        help_text.append("clear", style="bold cyan")
        help_text.append(" : Clears the screen and stops sniffing.\n", style="white")

        help_text.append("exit", style="bold cyan")
        help_text.append(" : Exits the application.\n", style="white")

        help_text.append("test", style="bold cyan")
        help_text.append(" : Launches a simulated SYN and DNS flood attack.\n", style="white")

        help_text.append("help", style="bold cyan")
        help_text.append(" : Displays this help message.\n", style="white")

        # Use Panel for a bordered box around the help text
        help_panel = Panel(help_text, title="Commands", border_style="green")

        # Write the formatted panel to the output area
        self.app.output_area.write(help_panel)

    async def handle_exit(self, args):
        self.app.exit()  # Exit the application

    async def handle_unknown_command(self, args):
        self.app.output_area.write(f"Unknown or incomplete command")

    def show_attack_pane(self):
        attack_pane = self.app.query_one("#bottom-left-attack-pane")
        attack_pane.display = True

    def hide_attack_pane(self):
        attack_pane = self.app.query_one("#bottom-left-attack-pane")
        attack_pane.display = False

    def hide_interfaces(self) -> None:
        top_left_pane = self.app.query_one("#top-left-pane")
        top_left_pane.display = False

    def show_interfaces(self) -> None:
        top_left_pane = self.app.query_one("#top-left-pane")
        top_left_pane.display = True

    async def handle_test(self, args):
        # Use the currently sniffing interface or default to a loopback if none is active
        interface = self.current_interface if self.current_interface else '\\Device\\NPF_Loopback'

        def launch_attacks(interface):
            victim_ip = get_local_ip()  # Get the victim IP for both attacks

            syn_thread = threading.Thread(target=simulate_syn_flood, args=(interface, victim_ip))
            dns_thread = threading.Thread(target=simulate_dns_flood, args=(interface, victim_ip))

            syn_thread.start()
            dns_thread.start()

        simulation_thread = threading.Thread(target=launch_attacks, args=(interface,))
        simulation_thread.start()
        self.app.output_area.write(f"Initiating attack simulation on {interface}\n")

    def start_sniffing_on_interface(self, iface_name):
        self.app.output_area.clear()
        self.hide_interfaces()  # Hide top left pane when sniffing starts
        self.hide_attack_pane()
        self.app.attack_output_area.clear()
        self.app.output_area.write(f"Sniffing on interface {iface_name}...\n")
        self.app.sniffing_active = True
        self.app.query_one(PacketFlowPlot).start_tracking()
        self.app.query_one(IPDistributionTable).reset()
        parser.reset_packet_counts()
        parser.reset_packet_counter()
        parser.start_time = time.time()
        start_sniffing(iface_name,
                       lambda packet: parser.parse_packet(packet,
                                                          self.app.output_area.write,
                                                          self.app.handle_attack_alert),
                       lambda: self.app.sniffing_active)
        self.app.set_timer(5, self.check_for_no_packets)

    def check_for_no_packets(self):
        if parser.packet_counter == 0:
            self.app.output_area.write("No packets captured. Are you running with administrator/root privileges?\n")
