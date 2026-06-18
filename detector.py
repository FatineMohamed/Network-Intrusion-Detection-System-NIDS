from scapy.all import sniff
from scapy.layers.inet import IP,TCP,UDP
from collections import defaultdict
import time
from database import save_alerts
from datetime import datetime
from scapy.all import conf

print(conf.iface)

syn_tracker = defaultdict(list)
udp_tracker = defaultdict(list)
port_scan_tracker = defaultdict(list)

alerted_ips = set()
udp_alerted = set()
port_scan_alerted = set()

SYN_THRESHOLD = 100
SYN_WINDOW = 10

UDP_THRESHOLD = 100
UDP_WINDOW = 10

PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 10

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        
        src_ip = packet[IP].src
        tcp_flags = packet[TCP].flags
        dst_port = None
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport

        if dst_port:
            current_time = time.time()
            port_scan_tracker[src_ip].append((
                dst_port, current_time)
            )

        if tcp_flags ==  "S":
            current_time = time.time()
            syn_tracker[src_ip].append(current_time)

            new_list = []
            new_entries = []
            
            for port, timestamp in port_scan_tracker[src_ip]:
                if current_time - timestamp <= PORT_SCAN_WINDOW:
                    new_entries.append((port,timestamp))

            port_scan_tracker[src_ip] = new_entries

            unique_ports = set()
            for port, timestamp in port_scan_tracker[src_ip]:
                unique_ports.add(port)

            port_count = len(unique_ports)
            
            for timestamp in syn_tracker[src_ip]:
                if current_time - timestamp <= SYN_WINDOW:
                    new_list.append(timestamp)

            syn_tracker[src_ip] = new_list

            count = len(syn_tracker[src_ip])

            if count >= SYN_THRESHOLD and src_ip not in alerted_ips:
                alerted_ips.add(src_ip)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                save_alerts(
                    timestamp,
                    src_ip,
                    "SYN Flood",
                    count
                )
                print(alerted_ips)
                print(
                    f"\n[ALERT] Possible SYN Flood Detected"
                    f"\n Source IP : {src_ip}"
                    f"\n SYN Packets : {count}\n",
                    flush=True
                )
               
            if port_count >= PORT_SCAN_THRESHOLD and src_ip not in port_scan_alerted:
                port_scan_alerted.add(src_ip)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                save_alerts(
                    timestamp,
                    src_ip,
                    "Port Scan",
                    port_count
                )
                print(port_scan_alerted)
                print(
                    f"\n[ALERT] Possible Port Scan Detected"
                    f"\n Source IP : {src_ip}"
                    f"\n Unique Ports : {port_count}\n",
                    flush=True
                )
                
    if packet.haslayer(IP) and packet.haslayer(UDP):
        src_ip = packet[IP].src
        current_time = time.time()
        udp_tracker[src_ip].append(current_time)
        new_list= []
        for timestamp in udp_tracker[src_ip]:
            if current_time - timestamp <= UDP_WINDOW:
                new_list.append(timestamp)
        
        udp_tracker[src_ip]=new_list
        udp_count = len(udp_tracker[src_ip])

        if(
            udp_count >= UDP_THRESHOLD and src_ip not in udp_alerted
        ):
            udp_alerted.add(src_ip)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_alerts(
                timestamp,
                    src_ip,
                    "UDP Flood",
                    udp_count
            )
            print("UDP threshold reached", flush=True)
            print(
                f"\n[ALERT] Possible UDP Flood Detected"
                f"\n Source IP : {src_ip}"
                f"\n UDP Packets: {udp_count}\n",
                flush=True
            )
                

print("Listening for SYN floods...")
sniff(
    iface="VMware Network Adapter VMnet8",
    prn=process_packet,
    store=False)        