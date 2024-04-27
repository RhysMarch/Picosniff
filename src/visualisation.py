# visualisation.py
import time

from textual.widget import Widget
from rich.table import Table
from packet_parser import parser
import plotext as plt
from textual_plotext import PlotextPlot


class PacketCountsTable(Widget):
    def on_mount(self):
        # Call some method to build the initial state of the table
        self.refresh_table()

    def refresh_table(self):
        self.table = Table(title="", style="#1e90ff")
        self.table.add_column("Protocol", justify="left", style="bright_white")
        self.table.add_column("Count", justify="left", style="bright_white")

        # Assuming packet_counts is a global variable or passed in some way
        for protocol, count in parser.packet_counts.items():
            self.table.add_row(protocol, str(count))

        # This tells Textual to refresh this widget
        self.refresh()

    def render(self):
        return self.table


class PacketFlowPlot(PlotextPlot):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
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
