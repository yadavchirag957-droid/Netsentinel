from detectors.icmp_anomaly import ICMPAnomalyDetector


detector = ICMPAnomalyDetector(
    packet_threshold=5,
    window_seconds=10
)


event = {
    "protocol": "ICMP",
    "src_ip": "192.168.56.3",
    "dst_ip": "192.168.56.10"
}


for i in range(5):

    result = detector.detect(event)

    print(f"Packet {i + 1}: {result}")
