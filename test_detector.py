from detector import PortScanDetector


detector = PortScanDetector(
    port_threshold=10,
    syn_threshold=5
)


features = {
    "source_ip": "192.168.56.3",
    "destination_ip": "192.168.56.10",
    "total_packets": 4,
    "unique_destination_ports": 3,
    "syn_count": 2,
    "window_seconds": 10,
}


alert = detector.detect(features)


if alert:
    print("🚨 ALERT")
    print(alert)
else:
    print("✅ No suspicious behaviour detected")
