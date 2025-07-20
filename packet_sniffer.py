from scapy.all import sniff, IP, TCP, UDP, Raw
def packet_callback(packet):
    print("="*60)

    if IP in packet:
        ip_layer = packet[IP]
        print(f"[+] IP Packet: {ip_layer.src} --> {ip_layer.dst}")
        print(f"    Protocol: {ip_layer.proto}")

    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"[+] TCP Segment: {tcp_layer.sport} --> {tcp_layer.dport}")

    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"[+] UDP Segment: {udp_layer.sport} --> {udp_layer.dport}")

    if Raw in packet:
        print(f"[+] Payload: {packet[Raw].load}")

# Start sniffing (root/sudo required)
print(" Starting packet sniffer... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)

