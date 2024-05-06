"""
visualisation.py

This module provides visualisation widgets for the Picosniff application, leveraging the Textual framework
to display packet traffic statistics and a real-time packet flow plot in a terminal interface.

Classes:
- PacketCountsTable: A Textual widget that displays a table of packet counts by protocol.
- PacketFlowPlot: A Textual widget that uses the Plotext library to plot packet flow over time.

The PacketCountsTable widget shows the number of packets captured for each network protocol, updating
in real-time as new data is received. The PacketFlowPlot widget graphs the rate of packets received over
time, providing a visual representation of network activity.

Usage:
The widgets are intended to be integrated with the main Textual application interface of Picosniff.
They are dynamically updated and provide the user with real-time data visualisation of network traffic.

Dependencies:
- Textual: Used to create the UI components in a terminal-based environment.
- Plotext: Utilised for plotting real-time data within the terminal.
- packet_parser: Provides the data needed by fetching packet counts and other metrics.

Examples:
Widgets from this module are instantiated and managed within the Picosniff Textual application. They
are not standalone and require packet data provided by packet_parser to function correctly.

PacketCountsTable:
- Displays real-time updates of packet counts for various network protocols such as IP, TCP, etc.

PacketFlowPlot:
- Plots the number of packets received over time on a graph with time on the X-axis and packet count on the Y-axis.
- Starts and stops tracking based on user interaction with the main application to control packet sniffing.

"""

from collections import Counter
import time
from textual.widget import Widget
from rich.table import Table
from packet_parser import parser
from textual_plotext import PlotextPlot


class PacketCountsTable(Widget):
    def on_mount(self):
        # Call some method to build the initial state of the table
        self.refresh_table()

    def refresh_table(self):
        self.table = Table(title="", style="#1e90ff")
        self.table.add_column("Protocol", justify="left", style="bright_white")
        self.table.add_column("Count", justify="left", style="bright_white")

        total_packets = 0  # Initialize total packet count

        # Loop through each protocol and count, adding a row for each
        for protocol, count in parser.packet_counts.items():
            self.table.add_row(protocol, str(count))
            total_packets += count  # Sum up the packet count for the total

        # After all individual protocol rows are added, add a total row
        self.table.add_row("Total", str(total_packets), end_section=True)

        # This method refreshes the widget to display the updated table
        self.refresh()

    def render(self):
        return self.table


class PacketFlowPlot(PlotextPlot):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.plt.title("Packet Flow Over Time")
        self.plt.xlabel("Time (seconds)")
        self.plt.ylabel("Packets")
        self.plt.grid = True
        self._last_plot_time = time.time()
        self._data = []  # Initialize with empty data
        self._packet_count_last_second = 0
        self._start_time = time.time()
        self._tracking_started = False
        self._initialize_plot()

    def _initialize_plot(self):
        # Set default data points to ensure axis labels are displayed
        self.plt.xlim(0, 60)  # 1 minute initial range
        self.plt.ylim(0, 10)  # Start with a simple range for y-axis
        self.plt.plot([0, 60], [0, 0])  # Plot an initial line at y=0
        self.refresh()  # Refresh immediately to draw the initial state

    def on_mount(self):
        self.set_interval(1, self.refresh_graph)

    def start_tracking(self):
        self._start_time = time.time()
        self._tracking_started = True

    def reset(self):
        self._data = []
        self._tracking_started = False

    def refresh_graph(self):
        if not self._tracking_started:
            return  # Do nothing if tracking hasn't begun

        current_time = time.time()
        current_count = parser.packet_counter
        packets_this_second = current_count - self._packet_count_last_second
        self._data.append((current_time - self._start_time, packets_this_second))
        self._packet_count_last_second = current_count

        if current_time - self._last_plot_time >= 1:
            self.replot()
            self._last_plot_time = current_time

    def replot(self):
        self.plt.clear_data()
        if self._data:
            times, counts = zip(*self._data[-60:])
            self.plt.plot(times, counts)

            if len(times) > 1:  # Ensure there's enough data for dynamic ranges
                self.plt.xlim(min(times), max(times))

            # Handle empty 'counts' case
            if counts:
                self.plt.ylim(0, max(counts) + 10)  # Adjust y-axis limit
            else:
                self.plt.ylim(0, 1)  # Default y-axis limit
        else:
            self.plt.plot([0, 60], [0, 0])
        self.refresh()


class PacketCountsBarChart(PlotextPlot):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.plt.width = 30  # Adjust width as needed
        self.plt.colorless = True
        self.plt.title("Packet Counts by Protocol")

    def on_mount(self):
        self.update_chart()

    def update_chart(self):
        self.plt.clear_data()
        protocols = [protocol for protocol, _ in parser.packet_counts.items()]
        counts = [count for _, count in parser.packet_counts.items()]

        self.plt.bar(protocols, counts)
        self.plt.ylim(0, max(counts) + 1 if counts else 1)  # Set Y-axis minimum to 0 and adjust maximum
        self.refresh()


class IPDistributionTable(Widget):
    def on_mount(self):
        self.refresh_table()  # Initialize on mount

    def refresh_table(self):
        self.table = Table(style="#1e90ff")
        self.table.add_column("IP Address", justify="left", style="bright_white")
        self.table.add_column("Count", justify="left", style="bright_white")

        if parser.ip_distribution:
            ip_counts = Counter(parser.ip_distribution.keys())
            for ip, count in sorted(parser.ip_distribution.items(), key=lambda item: item[1], reverse=True)[:10]:
                self.table.add_row(ip, str(count))

        self.refresh()  # Update the display

    def render(self):
        return self.table
