import time


class AlertDeduplicator:

    def __init__(self, cooldown_seconds=30):
        self.cooldown_seconds = cooldown_seconds
        self.last_alerts = {}

    def should_alert(self, alert):

        detection = alert.get("detection", "Unknown Detection")
        source_ip = alert.get("source_ip", "Unknown Source")
        destination_ip = alert.get(
            "destination_ip",
            "Unknown Destination"
        )

        key = (
            detection,
            source_ip,
            destination_ip
        )

        current_time = time.time()

        last_time = self.last_alerts.get(key)

        if last_time is not None:

            if current_time - last_time < self.cooldown_seconds:
                return False

        self.last_alerts[key] = current_time

        return True
