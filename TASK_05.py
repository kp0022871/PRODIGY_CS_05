from scapy.all import sniff, IP, Raw

def capture_packets(network_interface):
    def process_packet(packet):
        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            print(f"Source IP: {source_ip} --> Destination IP: {dest_ip} Protocol: {protocol}")

            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', 'ignore')
                print(f"Payload: {payload}")

    print(f"Sniffing packets on interface {network_interface}...")
    sniff(iface=network_interface, prn=process_packet, store=False)

# Specify the network interface to capture packets from
network_interface = "eth0"  # Replace with your network interface name
capture_packets(network_interface)