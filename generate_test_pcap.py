from scapy.all import IP, TCP, wrpcap


packets = []

source_ip = "192.168.56.3"
target_ip = "192.168.56.10"


for port in range(20, 40):

    packet = (
        IP(
            src=source_ip,
            dst=target_ip
        )
        /
        TCP(
            sport=40000,
            dport=port,
            flags="S"
        )
    )

    packets.append(packet)


wrpcap(
    "test_scan.pcap",
    packets
)


print("[+] Test PCAP created: test_scan.pcap")
print(f"[+] Packets generated: {len(packets)}")
