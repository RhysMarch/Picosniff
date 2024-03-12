import os
import platform


class CLIHandler:
    def __init__(self, packet_sniffer):
        self.packet_sniffer = packet_sniffer
        self.restart_required = False
        self.commands = {
            'help': self.show_help,
            'sniff': self.packet_sniffer.choose_interface_and_sniff,
            'clear': self.clear_output,  # Adding the 'clear' command
        }

    def run_cli(self):
        while not self.restart_required:
            print("\nCommands: 'sniff', 'help', 'clear', 'settings (wip)', 'save (wip)', 'exit'")
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

        return self.restart_required

    def show_help(self):
        print("")
        print("  sniff [interface number] - Start packet sniffing on the chosen interface")
        print("  clear - Restart the program")
        print("  settings - Change Picosniff settings")
        print("  save - Save previous sniffer output")
        print("  exit - Exit the program")

    def clear_output(self):
        os.system('cls' if platform.system() == "Windows" else 'clear')
        self.restart_required = True
