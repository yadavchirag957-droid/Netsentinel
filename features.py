from collections import defaultdict
from datetime import datetime


class FeatureExtractor:

    def __init__(self):
        self.connections = defaultdict(list)

    def add_event(self, event):
        source_ip = event["src_ip"]
        destination_ip = event["dst_ip"]

        key = (source_ip, destination_ip)

        self.connections[key].append(event)

    def get_features(self, source_ip, destination_ip, window_seconds=10):

        key = (source_ip, destination_ip)

        events = self.connections.get(key, [])

        if not events:
            return None

        now = datetime.fromisoformat(events[-1]["timestamp"])

        recent_events = []

        for event in events:

            event_time = datetime.fromisoformat(event["timestamp"])

            difference = (now - event_time).total_seconds()

            if difference <= window_seconds:
                recent_events.append(event)

        destination_ports = set()
        syn_count = 0

        for event in recent_events:

            if event["dst_port"] is not None:
                destination_ports.add(event["dst_port"])

            if event["tcp_flags"] and "S" in event["tcp_flags"]:
                syn_count += 1

        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "total_packets": len(recent_events),
            "unique_destination_ports": len(destination_ports),
            "syn_count": syn_count,
            "window_seconds": window_seconds,
        }
