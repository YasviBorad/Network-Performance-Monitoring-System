import scapy.all as scapy
import matplotlib.pyplot as plt
from collections import Counter
import threading
import time

# Global variables to store packet counts
packet_count = 0
protocol_counter = Counter()

def packet_callback(packet):
    global packet_count
    packet_count += 1
    # Count protocols
    if packet.haslayer(scapy.IP):
        protocol = packet[scapy.IP].proto
        protocol_counter[protocol] += 1

def start_sniffing(interface):
    print(f"Starting packet capture on {interface}...")
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

def display_stats():
    while True:
        time.sleep(5)  # Update every 5 seconds
        print(f"Total packets captured: {packet_count}")
        print("Protocol counts:")
        for proto, count in protocol_counter.items():
            print(f"Protocol {proto}: {count}")
        print("-" * 40)

if __name__ == "__main__":
    interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
    
    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start displaying stats
    display_stats()