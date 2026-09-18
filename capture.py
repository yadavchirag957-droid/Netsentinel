from scapy.all import sniff
from alert_pipeline import AlertPipeline

from parser import parse_packet
from features import FeatureExtractor

from detectors.port_scan import PortScanDetector
from detectors.icmp_anomaly import ICMPAnomalyDetector
from detectors.dns_anomaly import DNSAnomalyDetector
from detectors.dos_anomaly import DoSAnomalyDetector

from detection_engine import DetectionEngine


# ============================================================
# NetSentinel Configuration
# ============================================================

INTERFACE = "eth0"
FEATURE_WINDOW = 10


# ============================================================
# Core Components
# ============================================================

feature_extractor = FeatureExtractor()


# ============================================================
# Detection Modules
# ============================================================

port_scan_detector = PortScanDetector(
    port_threshold=10,
    syn_threshold=5
)

icmp_detector = ICMPAnomalyDetector(
    packet_threshold=50,
    window_seconds=10
)

dns_detector = DNSAnomalyDetector(
    query_threshold=30,
    window_seconds=10
)

dos_detector = DoSAnomalyDetector(
    packet_threshold=100,
    window_seconds=10
)


# ============================================================
# Unified Detection Engine
# ============================================================

detection_engine = DetectionEngine(
    detectors=[
        port_scan_detector,
        icmp_detector,
        dns_detector,
        dos_detector
    ]
)


# ============================================================
# Alert / Risk Components
# ============================================================

alert_pipeline = AlertPipeline()

# ============================================================
# Startup Information
# ============================================================

print("[*] NetSentinel started")
print(f"[*] Monitoring interface: {INTERFACE}")
print("[*] Detection engine: Enabled")
print("[*] Detectors:")
print("    - TCP Port Scan")
print("    - ICMP Anomaly")
print("    - DNS Query Anomaly")
print("    - DoS-like Traffic")
print("[*] Risk engine: Enabled")
print("[*] Alert deduplication: Enabled")
print("[*] Waiting for traffic...\n")


# ============================================================
# Packet Processing
# ============================================================

def process_packet(packet):

    event = parse_packet(packet)

    if not event:
        return

    feature_extractor.add_event(event)

    features = feature_extractor.get_features(
        event["src_ip"],
        event["dst_ip"],
        window_seconds=FEATURE_WINDOW
    )

    if not features:
        return

    detections = detection_engine.detect(
        event=event,
        features=features
    )

    if not detections:
        return
    for detection in detections:

        alert = alert_pipeline.process_detection(
            detection=detection,
            features=features
        )

        if alert:

            print(
                f"[+] Security event generated | "
                f"Detection: {alert['detection']} | "
                f"Risk: {alert['risk_score']} | "
                f"Severity: {alert['severity']}"
            )

        else:

            print(
                f"[*] Duplicate alert suppressed | "
                f"Detection: {detection['detection']}"
            )
# ============================================================
# Live Packet Capture
# ============================================================

sniff(
    iface=INTERFACE,
    prn=process_packet,
    store=False
)
