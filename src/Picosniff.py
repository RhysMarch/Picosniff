from packet_sniffer import *


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
    picosniff_ascii()
    PacketSniffer()


if __name__ == '__main__':
    main()