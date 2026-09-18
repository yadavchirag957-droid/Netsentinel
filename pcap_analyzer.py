from scapy.all import rdpcap

from parser import parse_packet
from features import FeatureExtractor


class PCAPAnalyzer:

    def __init__(self, detection_engine):

        self.detection_engine = detection_engine
        self.feature_extractor = FeatureExtractor()

    def analyze(self, pcap_file):

        packets = rdpcap(pcap_file)

        results = []

        for packet in packets:

            event = parse_packet(packet)

            if not event:
                continue

            self.feature_extractor.add_event(event)

            features = self.feature_extractor.get_features(
                event["src_ip"],
                event["dst_ip"],
                window_seconds=10
            )

            detections = self.detection_engine.detect(
                event=event,
                features=features
            )

            if detections:

                for detection in detections:

                    results.append({
                        "detection": detection,
                        "features": features
                    })

        return results
