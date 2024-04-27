# visualisation.py
from textual.widget import Widget
from rich.table import Table
from packet_parser import parser


class PacketCountsTable(Widget):
    def on_mount(self):
        # Call some method to build the initial state of the table
        self.refresh_table()

    def refresh_table(self):
        self.table = Table(title="")
        self.table.add_column("Protocol", justify="left", style="bright_cyan")
        self.table.add_column("Count", justify="left", style="bright_white")

        # Assuming packet_counts is a global variable or passed in some way
        for protocol, count in parser.packet_counts.items():
            self.table.add_row(protocol, str(count))

        # This tells Textual to refresh this widget
        self.refresh()

    def render(self):
        return self.table
