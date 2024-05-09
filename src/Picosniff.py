"""
Picosniff.py

This module defines the PicosniffApp class, a Textual user interface application
designed to monitor and visualise network traffic in real-time. The application
uses the Scapy library to parse network packets and displays various statistics
and details about the traffic through the interface.

Features:
- Dynamic packet monitoring with support for multiple network protocols including IP, TCP, UDP, DNS, DHCP, HTTP, and NTP.
- Real-time visualisations of network traffic through the interface.
- A command input system allowing the user to start and stop packet sniffing, clear the display, and handle other utility commands.

Structure:
- The app's layout is divided into several key areas:
  - `top-left-pane`: Displays the ASCII logo and network interfaces information.
  - `middle-left-pane`: Contains input commands for controlling packet sniffing and other utilities.
  - `right-pane`: Dedicated to displaying useful visuals.
  - `bottom-left-pane`: Acts as the output log for sniffed packet details and system messages.

Usage:
- The user can start and stop the packet sniffing process and interact with the application through textual commands inputted in the middle left pane.
- Visuals are shown in the right pane, providing live network traffic data.

Dependencies:
- Scapy for packet capture and analysis.
- Textual framework for the interactive UI.
"""
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll, Horizontal, Vertical
from textual.widgets import Static, Input, RichLog
from utils import ascii_logo, get_interfaces_info
from tui_handler import handle_command, CommandHandler
from visualisation import PacketCountsTable, PacketFlowPlot, PacketCountsBarChart, IPDistributionTable


class PicosniffApp(App):
    CSS_PATH = "style.tcss"

    def __init__(self) -> None:
        super().__init__()
        self.input_field = Input(placeholder="Type a command here")
        self.output_area = RichLog()
        self.attack_output_area = RichLog()
        self.sniffing_active = False
        self.packet_counts_table = PacketCountsTable()
        self.command_handler = CommandHandler(self)  # Pass the app instance to the command handler

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="left-section"):
                # Top Left Pane (for logo and network interface(s) display)
                with VerticalScroll(id="top-left-pane"):
                    yield Static(ascii_logo(), id="logo")
                    yield Static(get_interfaces_info())

                # Middle Left Pane (for command input)
                with Vertical(id="middle-left-pane"):
                    yield Static(" Commands: 'sniff', 'stop', 'clear', 'help', 'settings', 'save', 'exit'\n",
                                 id="commands")
                    yield self.input_field

                # Bottom Left Pane (for output)
                with VerticalScroll(id="bottom-left-pane"):
                    yield self.output_area

                # Bottom Left Pane (for attack detection output - initially hidden)
                with VerticalScroll(id="bottom-left-attack-pane") as attack_pane:  # Assign the container to a variable
                    yield self.attack_output_area
                attack_pane.display = False

            # Right Pane (dedicated to visualisations)
            with VerticalScroll(id="right-pane"):
                yield PacketFlowPlot(id="packet-flow-plot")
                with Horizontal(id="second-row"):
                    yield PacketCountsBarChart(id="packet-counts-barchart")
                    yield PacketCountsTable(id="packet-counts-table")
                yield IPDistributionTable(id="ip-distribution")

    async def on_mount(self):
        self.input_field.focus()
        self.set_interval(0.1, self.update_widgets)

    def handle_attack_alert(self, message):
        # Create a Text object with the message, styled in red
        formatted_message = Text(message, style="red3")
        self.attack_output_area.write(formatted_message)  # Write the formatted message to the log
        attack_pane = self.query_one("#bottom-left-attack-pane")
        attack_pane.display = True  # Ensure the attack output area is visible

    @on(Input.Submitted)
    async def handle_command_wrapper(self, event):
        await handle_command(self.command_handler, event)
        self.input_field.clear()

    async def update_widgets(self):
        packet_counts_widget = self.query_one(PacketCountsTable)
        packet_counts_widget.refresh_table()

        bar_chart_widget = self.query_one(PacketCountsBarChart)
        bar_chart_widget.update_chart()

        ip_distribution_chart = self.query_one(IPDistributionTable)
        ip_distribution_chart.refresh_table()


if __name__ == "__main__":
    PicosniffApp().run()
