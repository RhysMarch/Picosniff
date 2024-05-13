

![PicoSniff Logo](logo-no-background.png)

\
PicoSniff is a lightweight, user-friendly packet sniffer designed for 
network monitoring on both traditional and embedded systems. 
It's a terminal-based application that provides real-time 
packet capture and analysis, with features for visualising 
network traffic and detecting potential network threats.

## Features

- **Real-Time Packet Sniffing**: Capture and analyse network traffic as it happens.
- **Textual User Interface**: Simple and intuitive commands for operating the sniffer and configuring settings.
- **Data Visualization**: Graphical representation of network traffic flow and patterns.
- **Attack Detection**: Basic mechanisms to detect common network threats such as DoS attacks.

## Installation & Usage

To install PicoSniff, follow these steps:

1. Clone the repository to your local machine.
2. Navigate to the PicoSniff directory.
3. Optionally, create a virtual environment (`venv`) for isolated Python package management. Activate this environment.
4. Install the required dependencies with `pip install -r requirements.txt`.
5. Navigate to the `Picosniff/src` directory.
6. Run `Picosniff.py` as an administrator:
   - On Linux, use `sudo python Picosniff.py`.
   - On Windows, open the terminal as an administrator and execute `python Picosniff.py`.

## License

PicoSniff is available under a free-use license. This means that you can use, modify, and distribute the software without any restrictions. Please note that this software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

## Acknowledgements

- **Scapy Library**: Utilized for packet manipulation and sniffing capabilities.
- **Textual Framework**: Provides the foundation for the textual user interface.
- **Plotext**: Employs this library for generating plots and visuals of network data.
