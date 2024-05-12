"""
visualisation.py

This module provides visualisation widgets for the Picosniff application, leveraging the Textual framework
to display packet traffic statistics and a real-time packet flow plot in a terminal interface.

Classes:
- PacketCountsTable: A Textual widget that displays a table of packet counts by protocol.
- PacketFlowPlot: A Textual widget that uses the Plotext library to plot packet flow over time.
- PacketCountsBarChart: A Textual widget that displays a bar chart of packet counts by protocol.
- IPDistributionTable:  A Textual widget that displays a table of IP addresses, their packet
   counts, and WHOIS information. It distinguishes between local/private IPs and public IPs.

Features:
- Dynamic updates:  The widgets update in real-time as new packet data is received.
- Data reset: The widgets are automatically reset when a new packet sniffing session begins.
- Local IP identification: The IPDistributionTable highlights IP addresses that belong to the local machine.
- Informative WHOIS lookups: Provides organisation, country, and email information (when available) for public IP addresses.

Dependencies:
- Textual: Used to create the UI components in a terminal-based environment.
- Plotext: Utilised for plotting real-time data within the terminal.
- packet_parser: Provides the data needed by fetching packet counts and other metrics.
- ipaddress:  Used for classifying IP addresses.
- python-whois: Used to perform WHOIS lookups.
- threading: Used to update the WHOIs information on the table.
- socket: Used to identify local IP.

Usage:
The widgets are intended to be integrated with the main Textual application interface of Picosniff.
They are dynamically updated and provide the user with real-time data visualisation of network traffic.

"""
import time
import whois
import threading
import socket
import ipaddress
from collections import Counter, defaultdict
from textual.widget import Widget
from rich.table import Table
from packet_parser import parser
from textual_plotext import PlotextPlot


class PacketCountsTable(Widget):
    def on_mount(self):
        # Call some method to build the initial state of the table
        self.refresh_table()

    def refresh_table(self):
        self.table = Table(title="", style="#539eff")
        self.table.add_column("Protocol", justify="left", style="bright_white")
        self.table.add_column("Count", justify="left", style="bright_white")

        total_packets = 0  # Initialise total packet count

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
        self._data = []  # Initialise with empty data
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
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.local_ip = get_local_ip()
        self.whois_cache = defaultdict(lambda: 'Fetching...')
        self.init_table()

    def init_table(self):
        self.table = Table(title="IP Distribution", style="#539EFF")
        self.table.add_column("IP Address", justify="left", style="bright_white")
        self.table.add_column("Count", justify="left", style="bright_white")
        self.table.add_column("IP Info [dim](org, country, email)[/]", justify="left", style="bright_white")

    def on_mount(self):
        self.refresh_table()

    def refresh_table(self):
        self.init_table()  # Clear the existing table before refreshing
        if parser.ip_distribution:
            ip_counts = Counter(parser.ip_distribution)
            for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:15]:
                if ip not in self.whois_cache:
                    threading.Thread(target=self.fetch_whois_info, args=(ip,)).start()

                # Add (Yours) if the IP matches the local IP
                ip_label = ip + (" [purple](Yours)" if ip == self.local_ip else "")
                self.table.add_row(ip_label, str(count), self.whois_cache[ip])

        self.refresh()

    def reset(self):  # Add a reset method
        self.whois_cache.clear()
        parser.ip_distribution.clear()  # Clear the IP distribution data in your parser
        self.refresh_table()

    def fetch_whois_info(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback:
                info = f"[dim]Loopback IP"
            elif ip_obj.is_private:
                info = "Private Network IP"
            elif ip_obj.is_multicast:
                info = "Multicast Network IP"
            elif ip_obj.is_reserved:
                info = "Reserved IP"
            else:
                w = whois.whois(ip)
                # Apply Rich Styles
                org = f"[bold cyan]{w.get('org', 'No organisation found')}[/]"
                country = f"[dim]{w.get('country')}[/]"
                email = f"[yellow]{w.get('emails')[0]}[/]" if w.get('emails') else 'No email found'
                info = f"{org}, {country}, {email}"
            self.whois_cache[ip] = info
        except Exception:
            self.whois_cache[ip] = "WHOIS lookup failed"

    def render(self):
        return self.table


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        # Use Google's Public DNS server IP to find the local endpoint
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"  # Default to localhost if unable to determine
