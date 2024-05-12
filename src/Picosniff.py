"""
Picosniff.py

This module defines the PicosniffApp class, a Textual user interface application for real-time network traffic monitoring and analysis.
The application leverages the Scapy library for packet parsing and displays various statistics and details in an intuitive terminal-based interface.

Features:

-   **Dynamic Packet Monitoring:** Supports a wide range of network protocols including IP, TCP, UDP, DNS, DHCP, HTTP, ARP, and NTP.
-   **Real-time Visualisations:** Presents packet statistics and network activity trends in visually engaging formats:
    -   Packet counts table (total and per protocol)
    -   Dynamic line plot of packet flow over time
    -   Bar chart of packet counts by protocol
    -   IP distribution table with WHOIS lookups
-   **Command Input System:** Allows users to:
    -   Start/stop packet sniffing on selected interfaces
    -   Clear the display
    -   Access a comprehensive help guide
    -   Exit the application
-   **Attack Detection:** (Limited functionality) Alerts the user when potential SYN flood or DNS query flood attacks are detected.

Structure:

The TUI is divided into four main sections:
-   `top-left-pane`: Displays the ASCII logo and dynamically updates the list of available network interfaces. This pane can be hidden during active sniffing to maximise screen space.
-   `middle-left-pane`: Provides a command input area where users can enter commands to control Picosniff.
-   `right-pane`: Houses the real-time visualisations, providing a clear overview of network activity.
-   `bottom-left-pane`:  The main output log for packet details, system messages, and attack alerts.
-   `bottom-left-attack-pane`:  For when attack alerts are triggered, display attack cautions.

Usage:

1.  Launch Picosniff from your terminal.
2.  Select a network interface from the list in the top-left pane.
3.  Enter the 'sniff' command to start capturing packets.
4.  Monitor the packet details and visualisations in real time.
5.  Use the other commands (e.g., 'stop', 'help') as needed.

Dependencies:

-   Scapy: For packet capture, dissection, and analysis.
-   Textual: For building the interactive terminal-based user interface.
-   Rich: For enhanced text formatting and styling in the TUI.
"""
import time
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
        self.last_message_time = None

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

                # Bottom Left Attack Pane (for attack detection output - initially hidden)
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
        await self.command_handler.handle_help(None)
        self.set_interval(0.1, self.update_widgets)

    def handle_attack_alert(self, message):
        """Handles display of attack alerts and rate-limiting"""
        if "SYN" in message:
            color = "red3"
        elif "DNS" in message:
            color = "blue3"
        else:
            color = "bold yellow"  # For future attack detections

        if self.last_message_time and time.time() - self.last_message_time < 0.5:
            return  # Limit messages to once every 0.5 seconds

        formatted_message = Text(message, style=color)
        self.attack_output_area.write(formatted_message)
        attack_pane = self.query_one("#bottom-left-attack-pane")
        attack_pane.display = True  # Ensure the attack output area is visible
        self.last_message_time = time.time()  # Update timestamp

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
