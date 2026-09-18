from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP


def parse_packet(packet):

    if IP not in packet:
        return None

    data = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
    }

    if TCP in packet:
        data["protocol"] = "TCP"
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport
        data["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        data["protocol"] = "UDP"
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        data["protocol"] = "ICMP"

    return data
