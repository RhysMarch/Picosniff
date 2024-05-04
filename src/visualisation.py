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
        self._last_plot_time = 0
        self._data = []  # Store data points
        self._packet_count_last_second = 1
        self._start_time = None
        self._tracking_started = False  # Flag to track if time tracking has begun

    def on_mount(self):
        self.set_interval(1, self.refresh_graph)

    def start_tracking(self):
        self._start_time = time.time()
        self._tracking_started = True

    def reset(self):
        self._start_time = None
        self._data = []
        self._tracking_started = False
        self.replot()

    def refresh_graph(self):
        if not self._tracking_started:  # Check if tracking is active
            return  # Do nothing if tracking hasn't begun

        current_time = time.time()
        current_count = parser.packet_counter

        # Start tracking time if not yet started
        if self._start_time is None:
            self._start_time = current_time

        # Calculate packets received in the last second
        packets_this_second = current_count - self._packet_count_last_second
        self._data.append((current_time - self._start_time, packets_this_second))
        self._packet_count_last_second = current_count

        if current_time - self._last_plot_time >= 1:
            self.replot()
            self._last_plot_time = current_time

    def replot(self):
        if self._data:
            self.plt.clear_data()
            times, counts = zip(*self._data[-60:])  # Keep last 60 seconds of data

            self.plt.plot(times, counts)
            if len(times) > 1:
                self.plt.xlim(min(times), max(times))
            else:
                self.plt.xlim(0, 1)  # Default range to prevent division by zero

            if counts:
                self.plt.ylim(0, max(counts) + 10 if max(counts) > 0 else 1)
            else:
                self.plt.ylim(0, 1)  # Default range to prevent division by zero

            self.refresh()


class PacketCountsBarChart(PlotextPlot):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.plt.width = 30  # Adjust width as needed
        self.plt.colorless = True
        self.plt.title("Packet Counts by Protocol")
        self.plt.show_axes = False  # Initially hide both x and y axes

    def on_mount(self):
        self.update_chart()

    def update_chart(self):
        self.plt.clear_data()

        # Assuming you have packet_counts data from 'packet_parser'
        protocols = [protocol for protocol, _ in parser.packet_counts.items()]
        counts = [count for _, count in parser.packet_counts.items()]

        self.plt.bar(protocols, counts)
        self.plt.ticks_color("bright_white")  # Style adjustments
        self.plt.show()
        self.refresh()
