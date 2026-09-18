from alert_pipeline import AlertPipeline


pipeline = AlertPipeline()


detection = {
    "detection": "TCP Port Scan",
    "source_ip": "192.168.56.3",
    "destination_ip": "192.168.56.10",
    "protocol": "TCP",
    "unique_destination_ports": 25,
    "syn_count": 15
}


features = {
    "unique_destination_ports": 25,
    "syn_count": 15,
    "total_packets": 30,
    "window_seconds": 10
}


alert = pipeline.process_detection(
    detection=detection,
    features=features
)


print("\n=== NetSentinel Alert Pipeline Test ===\n")

if alert:
    print("[+] Alert generated successfully")
    print(f"Detection   : {alert['detection']}")
    print(f"Source IP   : {alert['source_ip']}")
    print(f"Target IP   : {alert['destination_ip']}")
    print(f"Severity    : {alert['severity']}")
    print(f"Risk Score  : {alert['risk_score']}")
    print(f"Confidence  : {alert['confidence']}")
    print(f"Status      : {alert['status']}")
    print("\nEvidence:")
    print(alert["evidence"])
else:
    print("[*] Alert was suppressed by deduplication.")

print("\n=== Test Complete ===\n")
