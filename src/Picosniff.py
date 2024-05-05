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
from tui_handler import handle_command, CommandHandler
from visualisation import PacketCountsTable, PacketFlowPlot, PacketCountsBarChart


class PicosniffApp(App):
    CSS_PATH = "style.tcss"

    def __init__(self) -> None:
        super().__init__()
        self.input_field = Input(placeholder="Type a command here")
        self.output_area = RichLog()
        self.sniffing_active = False
        self.packet_counts_table = PacketCountsTable()
        self.command_handler = CommandHandler(self)  # Pass the app instance to the command handler

    def compose(self) -> ComposeResult:
        with Container(id="app-grid"):

            # Top Left Section
            self.top_left_pane = Container(id="top-left-pane")
            with self.top_left_pane:
                interfaces_info = get_interfaces_info()
                yield Static(ascii_logo(), id="logo")
                yield Static(interfaces_info, id="interfaces")

            # Middle Left Section
            with VerticalScroll(id="middle-left-pane"):
                yield Static(" Commands: 'sniff', 'stop', 'clear', 'help', 'settings', 'save', 'exit'\n", id="commands")
                yield self.input_field

            # Right Section
            with Container(id="right-pane"):
                with VerticalScroll(id="packet-flow-plot-section"):
                    yield PacketFlowPlot(id="packet-flow-plot")
                with VerticalScroll(id="packet-counts-barchart-section"):
                    yield PacketCountsBarChart(id="packet-counts-barchart")
                with VerticalScroll(id="packet-counts-table-section"):
                    yield PacketCountsTable(id="packet-counts-table")

            # Bottom Left Section
            with VerticalScroll(id="bottom-left-pane"):
                yield self.output_area

    def hide_top_left_pane(self):
        self.top_left_pane.display = False

    def show_top_left_pane(self):
        self.top_left_pane.display = True

    async def on_mount(self):
        self.input_field.focus()
        self.set_interval(0.1, self.update_widgets)

    @on(Input.Submitted)
    async def handle_command_wrapper(self, event):
        await handle_command(self.command_handler, event)
        self.input_field.clear()

    async def update_widgets(self):
        packet_counts_widget = self.query_one(PacketCountsTable)
        packet_counts_widget.refresh_table()

        # Refresh bar chart
        bar_chart_widget = self.query_one(PacketCountsBarChart)
        bar_chart_widget.update_chart()


if __name__ == "__main__":
    PicosniffApp().run()
