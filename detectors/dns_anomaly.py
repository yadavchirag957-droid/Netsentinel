import time


class DNSAnomalyDetector:

    def __init__(self, query_threshold=30, window_seconds=10):
        self.query_threshold = query_threshold
        self.window_seconds = window_seconds
        self.queries = {}

    def detect(self, event, features=None):

        if event.get("protocol") != "DNS":
            return None

        source_ip = event.get("src_ip")
        destination_ip = event.get("dst_ip")

        if not source_ip:
            return None

        current_time = time.time()

        if source_ip not in self.queries:
            self.queries[source_ip] = []

        self.queries[source_ip].append(current_time)

        self.queries[source_ip] = [
            timestamp
            for timestamp in self.queries[source_ip]
            if current_time - timestamp <= self.window_seconds
        ]

        query_count = len(self.queries[source_ip])

        if query_count >= self.query_threshold:

            return {
                "detection": "Possible DNS Query Anomaly",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "query_count": query_count,
                "window_seconds": self.window_seconds
            }

        return None
