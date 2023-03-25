import argparse
import logging
from scapy.all import *

logging.basicConfig(level=logging.INFO, format='%(message)s')


# Constants
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ARP_TIMEOUT = 5


# Method for verifying subnet address is valid
def is_valid_ipv4_cidr(cidr):
    # Split the CIDR notation into the IP address and the prefix length
    try:
        ip_address, prefix_length = cidr.split('/')
    except ValueError:
        logging.error('Please enter a valid IPv4 range in CIDR notation')
        exit()

    # Check if the IP address is valid and all of its octets are in the range 0-255
    try:
        octets = [int(octet) for octet in ip_address.split('.')]
        if not all(0 <= octet <= 255 for octet in octets):
            logging.error('Please enter a valid IPv4 range in CIDR notation')
            exit()
    except ValueError:
        logging.error('Please enter a valid IPv4 range in CIDR notation')
        exit()

    # Check if the prefix length is an integer between 0 and 32
    try:
        prefix_length = int(prefix_length)
        if not (0 <= prefix_length <= 32):
            logging.error('Please enter a valid IPv4 range in CIDR notation')
            exit()
    except ValueError:
        logging.error('Please enter a valid IPv4 range in CIDR notation')
        exit()

    # If all checks pass, return True
    return True


# Set up command-line argument parser
parser = argparse.ArgumentParser(description='Discover devices in a network using ARP')
parser.add_argument('target_ip', help='The target IPv4 address range in CIDR notation (e.g., 192.168.0.0/24)')
args = parser.parse_args()

# Check to verify IP range is valid
is_valid_ipv4_cidr(args.target_ip)

# Create packet's Ethernet layer
ether = Ether(dst=BROADCAST_MAC)

# Create packet's ARP layer
arp = ARP(pdst=args.target_ip)

# Combine Ethernet and ARP layers to create packet
packet = ether / arp

# Send out packets and listen for responses
result = srp(packet, timeout=ARP_TIMEOUT)[0]

# Extract IP and MAC addresses from the result
clients = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
rawIP = [received.psrc for sent, received in result]

# Display captured IP and MAC addresses
logging.info("Available devices in the network:")
logging.info("IP" + " " * 18 + "MAC")
for client in clients:
    logging.info(client['ip'] + " " * (20 - len(client['ip'])) + client['mac'])


