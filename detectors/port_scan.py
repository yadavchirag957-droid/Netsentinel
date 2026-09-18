class PortScanDetector:

    def __init__(self, port_threshold=10, syn_threshold=5):
        self.port_threshold = port_threshold
        self.syn_threshold = syn_threshold

    def detect(self, event, features=None):

        if not features:
            return None

        unique_ports = features["unique_destination_ports"]
        syn_count = features["syn_count"]

        if (
            unique_ports >= self.port_threshold
            and syn_count >= self.syn_threshold
        ):
            return {
                "detection": "Possible Port Scan",
                "severity": "HIGH",
                "source_ip": features["source_ip"],
                "destination_ip": features["destination_ip"],
                "unique_ports": unique_ports,
                "syn_count": syn_count,
            }

        return None
