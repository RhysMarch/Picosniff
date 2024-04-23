# Picosniff.py
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static, Input, RichLog
from utils import ascii_logo, get_interfaces_info
from cli_handler import handle_command
from visualisation import PacketCountsTable


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
                yield PacketCountsTable(id="packet-counts-table")  # This yields the table widget to the layout
            with VerticalScroll(id="bottom-left-pane"):
                self.output_area = RichLog()
                yield self.output_area

    async def on_mount(self):
        self.input_field.focus()
        self.set_interval(0.1, self.update_packet_counts_table)

    @on(Input.Submitted)
    async def handle_command_wrapper(self, event):
        await handle_command(self, event)

    # Add a method to update the packet counts table
    async def update_packet_counts_table(self):
        # Grab the widget by querying it
        packet_counts_widget = self.query_one(PacketCountsTable)
        # Call the method on the widget to refresh its content
        packet_counts_widget.refresh_table()


if __name__ == "__main__":
    PicosniffApp().run()
