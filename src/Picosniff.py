from packet_sniffer import PacketSniffer
from cli_handler import CLIHandler


def picosniff_ascii():
    # ASCII Art generated using Patorjk's Text to ASCII Art Generator
    # Source: https://patorjk.com/software/taag/
    # Font: Slant
    print("""\
                    ____  _                       _ ________
                   / __ \(_)________  _________  (_) __/ __/
                  / /_/ / / ___/ __ \/ ___/ __ \/ / /_/ /_  
                 / ____/ / /__/ /_/ (__  ) / / / / __/ __/  
                /_/   /_/\___/\____/____/_/ /_/_/_/ /_/        
                                                                     
    """)


def main():
    restart = True
    while restart:
        picosniff_ascii()
        packet_sniffer = PacketSniffer()
        cli_handler = CLIHandler(packet_sniffer)
        restart = cli_handler.run_cli()


if __name__ == '__main__':
    main()
