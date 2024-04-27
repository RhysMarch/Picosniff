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
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static, Input, RichLog
from utils import ascii_logo, get_interfaces_info
from cli_handler import handle_command
from visualisation import PacketCountsTable, PacketFlowPlot


class PicosniffApp(App):
    CSS_PATH = "style.tcss"

    def __init__(self) -> None:
        super().__init__()
        self.sniffing_active = False
        self.packet_counts_table = PacketCountsTable()

    def compose(self) -> ComposeResult:
        with Container(id="app-grid"):
            with Container(id="top-left-pane"):
                interfaces_info = get_interfaces_info()
                yield Static(ascii_logo(), id="logo")
                yield Static(interfaces_info, id="interfaces")
            with VerticalScroll(id="middle-left-pane"):
                yield Static(" Commands: 'sniff', 'stop', 'clear', 'help', 'settings', 'save', 'exit'\n", id="commands")
                self.input_field = Input(placeholder="Type a command here")
                yield self.input_field
            with VerticalScroll(id="right-pane"):
                yield PacketFlowPlot(id="packet-flow-plot")  # This displays packet flow over time
                yield PacketCountsTable(id="packet-counts-table")  # This displays packet count by protocol type
            with VerticalScroll(id="bottom-left-pane"):
                self.output_area = RichLog()
                yield self.output_area

    async def on_mount(self):
        self.input_field.focus()
        self.set_interval(0.1, self.update_widgets)

    @on(Input.Submitted)
    async def handle_command_wrapper(self, event):
        await handle_command(self, event)

    # Add a method to update the packet counts table
    async def update_widgets(self):
        packet_counts_widget = self.query_one(PacketCountsTable)
        packet_counts_widget.refresh_table()


if __name__ == "__main__":
    PicosniffApp().run()
