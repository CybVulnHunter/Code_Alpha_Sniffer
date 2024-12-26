from scapy.all import *
from prettytable import PrettyTable

# Packet callback function to analyze captured packets
def packet_callback(packet):
    table = PrettyTable()
    table.field_names = ["Source IP", "Destination IP", "Protocol", "Details"]

    # Analyze IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        details = ""

        # Analyze TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            details = f"TCP {tcp_layer.sport} -> {tcp_layer.dport}, Flags: {tcp_layer.flags}"
            if tcp_layer.payload:
                details += f", Payload: {bytes(tcp_layer.payload).decode('utf-8', 'ignore')[:50]}..."

        # Analyze UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            details = f"UDP {udp_layer.sport} -> {udp_layer.dport}"

        # Analyze ICMP layer
        elif packet.haslayer(ICMP):
            details = "ICMP Packet"

        # Add to table
        table.add_row([src_ip, dst_ip, proto, details])
        print(table)

# Sniff packets on the network
print("[*] Starting network sniffer...")
sniff(prn=packet_callback, store=False)  # Set store to False to avoid memory overflow

