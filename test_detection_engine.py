from detection_engine import DetectionEngine
from detectors.icmp_anomaly import ICMPAnomalyDetector


icmp_detector = ICMPAnomalyDetector(
    packet_threshold=5,
    window_seconds=10
)

engine = DetectionEngine(
    detectors=[
        icmp_detector
    ]
)


event = {
    "protocol": "ICMP",
    "src_ip": "192.168.56.3",
    "dst_ip": "192.168.56.10"
}


for i in range(5):

    results = engine.detect(
        event=event,
        features={}
    )

    print(f"Packet {i + 1}: {results}")
