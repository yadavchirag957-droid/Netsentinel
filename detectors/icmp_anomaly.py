import time


class ICMPAnomalyDetector:

    def __init__(self, packet_threshold=50, window_seconds=10):
        self.packet_threshold = packet_threshold
        self.window_seconds = window_seconds
        self.events = {}

    def detect(self, event, features=None):

        if event.get("protocol") != "ICMP":
            return None

        source_ip = event.get("src_ip")
        destination_ip = event.get("dst_ip")

        if not source_ip or not destination_ip:
            return None

        key = (source_ip, destination_ip)
        current_time = time.time()

        if key not in self.events:
            self.events[key] = []

        self.events[key].append(current_time)

        # Keep only events inside the detection window
        self.events[key] = [
            timestamp
            for timestamp in self.events[key]
            if current_time - timestamp <= self.window_seconds
        ]

        packet_count = len(self.events[key])

        if packet_count >= self.packet_threshold:

            return {
                "detection": "Possible ICMP Flood/Anomaly",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "packet_count": packet_count,
                "window_seconds": self.window_seconds
            }

        return None
