import os
import logging
# Set logging level for Scapy to suppress unnecessary output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
from scapy.all import *
from datetime import datetime as dt
from scapy.config import conf
# Set Scapy's debug dissector level
conf.debug_dissector = 2

class BlackList:
    def __init__(self):
        self.path = "./black_list.txt"

        if not os.path.exists(self.path):
            os.system(f"touch {self.path}")

        with open(self.path, "r") as f:
            self.black_list = f.read().split("\n")   

    def read(self):
        return self.black_list

    def add(self, ip_list: list):
        # Append new IPs to the blacklist file and update iptables
        with open(self.path, "a") as f:
            for ip in ip_list:
                payload = f"{ip}" if len(self.black_list) == 0 else f"\n{ip}"
                f.write(payload)
               
                # Block the IP using iptables
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                print(f"the {ip} get banned")


def FindHacker(ip_list:list):
    dict_ = {}
    for i in ip_list:
        if i not in dict_.keys():
            dict_[i] = ip_list.count(i)

    return [i for i, j in dict_.items() if j > 5]


def BullyTheHacker(ip, dport, sport):
    # Create a TCP packet with SYN flag set to send to the hacker
    packet = IP(dst=ip) / TCP(dport=dport, sport=sport, flags="SA") / "ridi dadash :)"
    send(packet, verbose=False)  # Send the packet without verbose output


def options():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('-iface', required=True, type=str, help="the interface name")
    parser.add_argument('-ip', required=True, type=str, help="the ip address")

    args = parser.parse_args()
    
    return args.iface, args.ip


def main():
    target_list = []  # List to keep track of potential hacker IPs
    date_1 = dt.now()  # Initialize the timestamp for tracking time intervals
    INTER_FACE, HOST_IP = options()  # Get command-line arguments for interface and host IP
    
    def process_packet(p):
        global date_1
        black_ips = BlackList().read()  # Read the current blacklist

        # Check if the packet has a TCP layer
        if p.haslayer(TCP):
            packet = p[TCP]  # Extract the TCP layer

            # Get source IP and ports
            src_ip = str(packet).split()[1].split(":")[0]
            src_port = packet.sport
            dst_port = packet.dport

            # If the source IP is in the blacklist
            if src_ip in black_ips:
                BullyTheHacker(src_ip, src_port, dst_port)
                
            else:
                # If the source IP is not the host and the packet is a SYN
                if src_ip != HOST_IP and packet.flags == "S":
                    target_list.append(src_ip)  # Add the source IP to the target list
                    date_2 = dt.now()  # Get the current timestamp
                    
                    # Check if 3 seconds have passed since the last check
                    if (date_2 - date_1).seconds >= 3:
                        hackers_ip = FindHacker(target_list)  # Identify potential hackers

                        # If potential hackers are found, add them to the blacklist
                        if hackers_ip:
                            BlackList().add(hackers_ip)

                        date_1 = dt.now()  # Reset the timestamp
                        target_list.clear()  # Clear the target list for the next interval

    print("FireWall gets start")
    sniff(iface=INTER_FACE, prn=process_packet)  # Start sniffing packets on the specified interface

if __name__ == "__main__" and os.getuid() == 0:
    main()
else:
    print("the need to be ROOT \nrun this command:\nsudo python3 main.py {OPTIONS}")

# Done :)