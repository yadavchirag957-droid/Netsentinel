import time


class BruteForceDetector:

    def __init__(self, attempt_threshold=5, window_seconds=60):
        self.attempt_threshold = attempt_threshold
        self.window_seconds = window_seconds
        self.failed_attempts = {}

    def detect(self, event,features=None):

        if event.get("event_type") != "authentication_failure":
            return None

        source_ip = event.get("source_ip")

        if not source_ip:
            return None

        current_time = time.time()

        if source_ip not in self.failed_attempts:
            self.failed_attempts[source_ip] = []

        self.failed_attempts[source_ip].append(current_time)

        # Remove attempts outside the detection window
        self.failed_attempts[source_ip] = [
            timestamp
            for timestamp in self.failed_attempts[source_ip]
            if current_time - timestamp <= self.window_seconds
        ]

        attempt_count = len(self.failed_attempts[source_ip])

        if attempt_count >= self.attempt_threshold:

            return {
                "detection": "Possible SSH Brute Force",
                "source_ip": source_ip,
                "failed_attempts": attempt_count,
                "window_seconds": self.window_seconds
            }

        return None
