from collections import deque


class TrafficManager:

    def __init__(self, max_events=5000):
        self.max_events = max_events
        self.events = deque(maxlen=max_events)

    def add_event(self, event):
        self.events.append(event)

    def get_events(self, limit=500):
        events = list(self.events)
        return events[-limit:]

    def get_statistics(self):
        events = list(self.events)

        protocols = {}
        event_types = {}

        for event in events:
            protocol = event.get("protocol")
            event_type = event.get("event_type")

            if protocol:
                protocols[protocol] = protocols.get(protocol, 0) + 1

            if event_type:
                event_types[event_type] = (
                    event_types.get(event_type, 0) + 1
                )

        return {
            "total_events": len(events),
            "protocols": protocols,
            "event_types": event_types
        }
