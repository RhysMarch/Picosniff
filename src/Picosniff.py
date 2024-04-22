from textual import on
from textual.app import App, ComposeResult
from scapy.all import IFACES
from textual.containers import Container, VerticalScroll
from textual.widgets import Static, Input, RichLog
from rich.text import Text
from packet_sniffer import start_sniffing
from packet_parser import parse_packet
from utils import ascii_logo


def get_interfaces_info() -> Text:
    interfaces_info = Text("Available Network Interfaces:\n")
    for index, iface in enumerate(IFACES, 1):
        iface_obj = IFACES[iface]
        description = iface_obj.description or 'No description available'
        interfaces_info.append(f"{index}: {iface_obj.name} ({description})\n")
    return interfaces_info


class PicosniffApp(App):

    CSS_PATH = "style.tcss"

    def __init__(self) -> None:
        super().__init__()
        self.sniffing_active = False

    def compose(self) -> ComposeResult:
        with Container(id="app-grid"):
            with VerticalScroll(id="top-left-pane"):
                interfaces_info = get_interfaces_info()
                yield Static(ascii_logo())
                yield Static(interfaces_info)
            with VerticalScroll(id="middle-left-pane"):
                yield Static(" Commands: 'sniff', 'stop', 'clear', 'help', 'settings', 'save', 'exit'\n")
                self.input_field = Input(placeholder="Type a command here")
                yield self.input_field
            with VerticalScroll(id="right-pane"):
                yield Static("")
            with VerticalScroll(id="bottom-left-pane"):
                self.output_area = RichLog()
                yield self.output_area

    async def on_mount(self):
        self.input_field.focus()

    @on(Input.Submitted)
    async def handle_command(self, event):
        input_text = event.value.strip()
        command, *args = input_text.split()
        if command == "sniff" and args:
            iface_index = int(args[0])
            if 0 < iface_index <= len(IFACES):
                iface_name = IFACES[list(IFACES.keys())[iface_index - 1]].name
                self.output_area.write(f"Sniffing on interface {iface_name}...\n")
                self.sniffing_active = True
                start_sniffing(iface_name, lambda x: self.output_area.write(parse_packet(x) + "\n"), lambda: self.sniffing_active)
            else:
                self.output_area.write("Invalid interface index\n")
        elif command == "stop":
            self.sniffing_active = False
            self.output_area.write("Sniffing stopped\n")
        elif command == "clear":
            self.output_area.clear()
        else:
            self.output_area.write(f"Unknown or incomplete command: '{input_text}'.\n")
        self.input_field.value = ""


if __name__ == "__main__":
    PicosniffApp().run()
