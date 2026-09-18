import time


class DoSAnomalyDetector:

    def __init__(self, packet_threshold=100, window_seconds=10):
        self.packet_threshold = packet_threshold
        self.window_seconds = window_seconds
        self.traffic = {}

    def detect(self, event, features=None):

        source_ip = event.get("src_ip")
        destination_ip = event.get("dst_ip")

        if not source_ip or not destination_ip:
            return None

        current_time = time.time()

        key = (source_ip, destination_ip)

        if key not in self.traffic:
            self.traffic[key] = []

        self.traffic[key].append(current_time)

        self.traffic[key] = [
            timestamp
            for timestamp in self.traffic[key]
            if current_time - timestamp <= self.window_seconds
        ]

        packet_count = len(self.traffic[key])

        if packet_count >= self.packet_threshold:

            return {
                "detection": "Possible DoS-like Traffic",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "packet_count": packet_count,
                "window_seconds": self.window_seconds
            }

        return None
