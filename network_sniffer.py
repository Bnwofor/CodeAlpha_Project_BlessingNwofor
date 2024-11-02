import scapy.all as scapy

# Set network interface (e.g., eth0, wlan0)
iface = "eth0"

# Define packet callback function
def packet_sniffer(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print("Source IP: ", src_ip)
        print("Destination IP: ", dst_ip)
        print("Protocol: ",  protocol)

        # Check for TCP packets
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print("Source Port: ", src_port)
            print("Destination Port: ", dst_port)

        # Check for UDP packets
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print("Source Port: ", src_port)
            print("Destination Port: ", dst_port)

        # Check for ICMP packets
        elif packet.haslayer(scapy.ICMP):
            print("ICMP Packet")

        print("------------------------")

# Start sniffing
scapy.sniff(iface=iface, prn=packet_sniffer, store=0)
