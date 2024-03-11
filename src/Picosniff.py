from packet_sniffer import *


def picosniff_ascii():
    print("""\
        
       ___  _          ____     _ ______
      / _ \(_)______  / __/__  (_) _/ _/
     / ___/ / __/ _ \_\ \/ _ \/ / _/ _/ 
    /_/  /_/\__/\___/___/_//_/_/_//_/   
                                    
    """)


def main():
    picosniff_ascii()
    PacketSniffer()


if __name__ == '__main__':
    main()