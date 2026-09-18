from features import FeatureExtractor
from datetime import datetime, timedelta


extractor = FeatureExtractor()

now = datetime.now()

events = [
    {
        "timestamp": now.isoformat(),
        "src_ip": "192.168.56.3",
        "dst_ip": "192.168.56.10",
        "protocol": "TCP",
        "src_port": 50001,
        "dst_port": 22,
        "tcp_flags": "S",
    },
    {
        "timestamp": (now + timedelta(seconds=1)).isoformat(),
        "src_ip": "192.168.56.3",
        "dst_ip": "192.168.56.10",
        "protocol": "TCP",
        "src_port": 50002,
        "dst_port": 80,
        "tcp_flags": "S",
    },
    {
        "timestamp": (now + timedelta(seconds=2)).isoformat(),
        "src_ip": "192.168.56.3",
        "dst_ip": "192.168.56.10",
        "protocol": "TCP",
        "src_port": 50003,
        "dst_port": 443,
        "tcp_flags": "S",
    },
]


for event in events:
    extractor.add_event(event)


features = extractor.get_features(
    "192.168.56.3",
    "192.168.56.10",
    window_seconds=10
)

print(features)
