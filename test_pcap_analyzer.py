from detection_engine import DetectionEngine
from detectors.port_scan import PortScanDetector
from detectors.icmp_anomaly import ICMPAnomalyDetector
from detectors.dns_anomaly import DNSAnomalyDetector
from detectors.dos_anomaly import DoSAnomalyDetector

from pcap_analyzer import PCAPAnalyzer


detectors = [
    PortScanDetector(
        port_threshold=10,
        syn_threshold=5
    ),

    ICMPAnomalyDetector(
        packet_threshold=5,
        window_seconds=10
    ),

    DNSAnomalyDetector(
        query_threshold=30,
        window_seconds=10
    ),

    DoSAnomalyDetector(
        packet_threshold=100,
        window_seconds=10
    )
]


detection_engine = DetectionEngine(
    detectors=detectors
)


analyzer = PCAPAnalyzer(
    detection_engine=detection_engine
)


results = analyzer.analyze(
    "test_scan.pcap"
)


print("\n=== NetSentinel PCAP Investigation ===\n")

print(f"Packets analyzed successfully.")

if results:

    print(f"\n[+] Detections found: {len(results)}\n")

    for index, result in enumerate(results, start=1):

        print(f"Detection #{index}")
        print(f"Type        : {result.get('detection')}")
        print(f"Source IP   : {result.get('source_ip')}")
        print(f"Target IP   : {result.get('destination_ip')}")
        print()

else:

    print("[*] No suspicious behaviour detected.")

print("=== Investigation Complete ===")
