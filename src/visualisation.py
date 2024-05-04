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
        self.plt.xlim(0, 60)  # Initial x-axis range for 1 minute
        self.plt.ylim(0, 10)  # Initial y-axis range
        self._data = []
        self._last_plot_time = time.time()  # Track the last time we plotted
        self._packet_count_last_second = 0
        self._start_time = time.time()  # Start time for tracking
        self._tracking_started = False
        self.refresh()  # Draw initial plot

    def on_mount(self):
        self.set_interval(1, self.refresh_graph)

    def start_tracking(self):
        self._tracking_started = True
        self._start_time = time.time()
        self._last_plot_time = self._start_time

    def reset(self):
        self._tracking_started = False
        self._data = []
        self._start_time = time.time()
        self._last_plot_time = self._start_time
        self._packet_count_last_second = 0
        self.plt.xlim(0, 60)
        self.plt.ylim(0, 10)
        self.refresh()

    def refresh_graph(self):
        self.plt.clear_data()
        if not self._tracking_started:
            # Start with a baseline point to maintain axis range
            self.plt.plot([0], [0])
            self.plt.xlim(0, 60)
            self.plt.ylim(0, 10)
            self.refresh()
            return

        current_time = time.time()
        current_count = parser.packet_counter  # This needs to be provided by your packet capturing logic

        # Calculate packets per second
        packets_this_second = current_count - self._packet_count_last_second
        self._data.append((current_time - self._start_time, packets_this_second))
        self._packet_count_last_second = current_count

        # Replot only if necessary
        if current_time - self._last_plot_time >= 1:
            self.replot()
            self._last_plot_time = current_time

    def replot(self):
        self.plt.clear_data()
        if self._data:
            times, counts = zip(*self._data)
            self.plt.plot(times, counts)
            self.plt.xlim(min(times), max(times))
            self.plt.ylim(0, max(counts) + 10)
        else:
            self.plt.plot([], [])
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
