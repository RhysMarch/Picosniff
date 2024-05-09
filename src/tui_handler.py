"""
tui_handler.py

This module defines the command handling and UI display logic for a Textual-based network packet sniffing application.
It interprets user inputs, executes actions such as starting or stopping packet sniffing, clearing the display, or exiting the application. The module also renders help information in stylised panels.

Functions:
- handle_command(self, event): Parses and executes commands received through a textual input widget.
- handle_sniff(self, args): Initiates packet sniffing on a specified network interface.
- handle_stop(self, args): Stops the active packet sniffing session.
- handle_clear(self, args): Clears the display areas and stops packet sniffing.
- handle_help(self, args): Displays a help screen with command descriptions and information panels.
- handle_exit(self, args): Exits the application gracefully.
- handle_unknown_command(self, args): Provides feedback for unrecognised or malformed commands.
- handle_test(self, args):  Launches a simulated SYN and DNS flood attack for testing purposes.

Additional UI Functions:
- show_attack_pane(self): Makes the attack alerts panel visible.
- hide_attack_pane(self): Hides the attack alerts panel.
- show_interfaces(self): Shows the 'top-left' interface panel.
- hide_interfaces(self): Hides the 'top-left' interface panel.

Responsibilities:
- Manage the overall state of packet sniffing.
- Render user interface panels with Rich text formatting.
- Validate user commands and provide feedback.
- Coordinate with external modules for packet parsing, sniffing, and visualisation.

Dependencies:
- scapy.interfaces.IFACES: Used to validate and resolve network interface specifications.
- packet_parser:  Parses packets and manages packet counters.
- packet_sniffer:  Handles the packet sniffing process.
- visualisation: Contains widgets for displaying packet flow, packet counts, and IP distribution.
- attack_detection_test: Provides functions to simulate attacks.
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

        # Intro Text
        intro_text = Text()
        intro_text.append(
            "\n     Dive into network traffic with this easy-to-use terminal packet sniffer "
            "\n     (powered by Textual). Read the rest of this panel before using Picosniff.")
        self.app.output_area.write(intro_text)

        # Command Panel
        help_text = Text()
        help_text.append("\nCommands:\n", style="underline")
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
        self.app.output_area.write(help_text)

        # Visualisation Panel
        vis_text = Text()
        vis_text.append("Visualisations & Statistics:\n", style="underline")
        vis_text.append("Packet Flow Plot: ", style="yellow")
        vis_text.append("Shows real-time packet flow over time.\n", style="white")
        vis_text.append("Packet Counts Bar Chart: ", style="yellow")
        vis_text.append("Displays the count of packets by protocol.\n", style="white")
        vis_text.append("IP Distribution Table: ", style="yellow")
        vis_text.append("Lists the distribution of source and destination\nIPs in the traffic.\n", style="white")
        self.app.output_area.write(vis_text)

        # Attack Detection Panel
        attack_text = Text()
        attack_text.append("Attack Detection:\n", style="underline")
        attack_text.append("Real-time Attack Alerts: ", style="bold magenta")
        attack_text.append("Alerts for DNS Query Flood and SYN Flood attacks.\n", style="white")
        attack_text.append("Display on Detection: ", style="bold magenta")
        attack_text.append("Attack details are displayed in the bottom-left\nattack pane when detected.\n",
                           style="white")
        attack_text.append("False Warnings: ", style="bold magenta")
        attack_text.append("Attack detection needs to be fine-tuned perfectly depending \n on the network and therefore can give false warnings. "
                           "This can be solved \nby only investigating alerts with high rates of events per second.",
                           style="white")
        self.app.output_area.write(attack_text)

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

            self.app.output_area.write(victim_ip)
            self.app.output_area.write(interface)
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
