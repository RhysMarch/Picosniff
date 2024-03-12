class CLIHandler:
    def __init__(self, packet_sniffer):
        self.packet_sniffer = packet_sniffer
        self.commands = {
            'help': self.show_help,
            'sniff': self.packet_sniffer.choose_interface_and_sniff,
        }

    def run_cli(self):
        while True:
            print("\nCommands: 'sniff', 'help', 'exit'")
            cmd_input = input("\nPicoSniff> ")
            cmd_parts = cmd_input.split()

            cmd = cmd_parts[0]
            if cmd == 'sniff':
                if len(cmd_parts) > 1:
                    self.packet_sniffer.choose_interface_and_sniff(interface_number=cmd_parts[1])
                else:
                    self.packet_sniffer.choose_interface_and_sniff()
            elif cmd in self.commands:
                self.commands[cmd]()
            elif cmd == 'exit':
                break
            else:
                print("Unknown command. Type 'help' for a list of commands.")
    def show_help(self):
        print("Commands:")
        print("  sniff - Start packet sniffing")
        print("  exit - Exit the program")
