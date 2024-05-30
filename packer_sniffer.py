from scapy.all import *

def packet_callback(packet):
    print(packet.show())

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP Packet: {ip_src} -> {ip_dst} Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

interface = "eth0"  # Interface réseau à écouter, changez selon votre configuration
sniff_packets(interface)

