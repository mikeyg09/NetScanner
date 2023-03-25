This is a command-line tool for scanning the IPv4 and MAC addresses of devices on your local network.




Usage:

To use this tool, open a command prompt in the same directory as netscanner.py and run the command:


	python netscanner.py [IP address in CIDR notation]


You can determine your IP address CIDR notation by running the command ipconfig (for Windows) or ifconfig (for Linux/Mac) and noting the IPv4 address and subnet mask. Simply use an online converter to get the CIDR notation.


Installation:

To use this tool, you will need to have Python 3.x installed on your system.

You will also need to install the following Python packages:

argparse,
logging,
scapy

You can install these packages using pip:


	pip install argparse logging scapy


How It Works:
The tool sends an ARP broadcast packet to the target IP range and listens for responses. It extracts the IP and MAC addresses from the responses and displays them on the console.


