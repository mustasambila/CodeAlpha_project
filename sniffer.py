from scapy.all import sniff, IP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")

# Start sniffing
def start_sniffing(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Simple Network Sniffer")
    parser.add_argument("interface", help="Network interface to sniff on")
    args = parser.parse_args()

    start_sniffing(args.interface)
