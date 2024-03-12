class CLIHandler:
    def __init__(self, packet_sniffer):
        self.packet_sniffer = packet_sniffer
        self.commands = {
            'help': self.show_help,
            'sniff': self.packet_sniffer.choose_interface_and_sniff,
        }

    def run_cli(self):
        while True:
            print("\n Commands: 'sniff', 'help', 'exit'")
            cmd = input("\nPicoSniff> ")
            if cmd in self.commands:
                self.commands[cmd]()
            elif cmd == 'exit':
                break
            else:
                print("Unknown command. Type 'help' for a list of commands.")

    def show_help(self):
        print("Commands:")
        print("  sniff - Start packet sniffing")
        print("  exit - Exit the program")
