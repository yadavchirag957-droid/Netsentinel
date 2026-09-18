import csv
import random
from datetime import datetime, timedelta


OUTPUT_FILE = "traffic_generator/traffic_dataset.csv"

NORMAL_EVENTS_PER_BLOCK = 400
ATTACK_ROUNDS = 3

SOURCE_IPS = [
    "192.168.56.3",
    "192.168.56.4",
    "192.168.56.5",
    "192.168.56.6",
]

DESTINATION_IPS = [
    "192.168.56.10",
    "192.168.56.11",
    "192.168.56.12",
]


def normal_event(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "source_ip": random.choice(SOURCE_IPS),
        "destination_ip": random.choice(DESTINATION_IPS),
        "protocol": random.choice(["TCP", "UDP", "ICMP", "DNS"]),
        "destination_port": random.choice(
            [22, 53, 80, 443, 123, 8080]
        ),
        "packet_count": random.randint(1, 8),
        "event_type": "Normal",
    }


def port_scan_burst(start_time, source_ip, destination_ip):
    events = []

    for i, port in enumerate(range(10, 25)):
        events.append({
            "timestamp": (
                start_time + timedelta(seconds=i * 0.4)
            ).isoformat(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": "TCP",
            "destination_port": port,
            "packet_count": 1,
            "event_type": "Port Scan",
        })

    return events


def icmp_flood_burst(start_time, source_ip, destination_ip):
    events = []

    for i in range(60):
        events.append({
            "timestamp": (
                start_time + timedelta(seconds=i * 0.04)
            ).isoformat(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": "ICMP",
            "destination_port": "",
            "packet_count": 1,
            "event_type": "ICMP Flood",
        })

    return events


def dns_anomaly_burst(start_time, source_ip, destination_ip):
    events = []

    for i in range(35):
        events.append({
            "timestamp": (
                start_time + timedelta(seconds=i * 0.08)
            ).isoformat(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": "DNS",
            "destination_port": 53,
            "packet_count": 1,
            "event_type": "DNS Anomaly",
        })

    return events


def dos_burst(start_time, source_ip, destination_ip):
    events = []

    for i in range(120):
        events.append({
            "timestamp": (
                start_time + timedelta(seconds=i * 0.04)
            ).isoformat(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": "TCP",
            "destination_port": 80,
            "packet_count": 1,
            "event_type": "DoS",
        })

    return events


def main():

    current_time = datetime.now()
    events = []

    attack_types = [
        "Port Scan",
        "DNS Anomaly",
        "ICMP Flood",
        "DoS",
    ]

    attack_rounds = attack_types * ATTACK_ROUNDS
    random.shuffle(attack_rounds)

    attack_index = 0

    for block in range(len(attack_rounds)):

        # Normal traffic block
        for _ in range(NORMAL_EVENTS_PER_BLOCK):
            events.append(normal_event(current_time))
            current_time += timedelta(seconds=0.5)

        # Attack burst
        attack_type = attack_rounds[attack_index]

        source_ip = SOURCE_IPS[attack_index % len(SOURCE_IPS)]
        destination_ip = DESTINATION_IPS[
            attack_index % len(DESTINATION_IPS)
        ]

        if attack_type == "Port Scan":
            burst = port_scan_burst(
                current_time,
                source_ip,
                destination_ip
            )

        elif attack_type == "ICMP Flood":
            burst = icmp_flood_burst(
                current_time,
                source_ip,
                destination_ip
            )

        elif attack_type == "DNS Anomaly":
            burst = dns_anomaly_burst(
                current_time,
                source_ip,
                destination_ip
            )

        else:
            burst = dos_burst(
                current_time,
                source_ip,
                destination_ip
            )

        events.extend(burst)

        # Move timestamp beyond the attack burst
        current_time = (
            datetime.fromisoformat(events[-1]["timestamp"])
            + timedelta(seconds=5)
        )

        attack_index += 1

    with open(OUTPUT_FILE, "w", newline="") as file:

        fieldnames = [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "destination_port",
            "packet_count",
            "event_type",
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    counts = {}

    for event in events:
        event_type = event["event_type"]
        counts[event_type] = counts.get(event_type, 0) + 1

    print(f"[+] Dataset generated: {OUTPUT_FILE}")
    print(f"[+] Total events: {len(events)}")
    print("[+] Event distribution:")

    for event_type, count in counts.items():
        print(f"    - {event_type}: {count}")

    print("[+] Traffic pattern: NORMAL + MIXED ATTACK BURSTS")


if __name__ == "__main__":
    main()
