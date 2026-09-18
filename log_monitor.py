import time

from log_parser import LogParser
from detectors.brute_force import BruteForceDetector
from risk_engine import RiskEngine
from alert_manager import AlertManager
from alert_deduplicator import AlertDeduplicator


LOG_FILE = "auth_test.log"


parser = LogParser()

detector = BruteForceDetector(
    attempt_threshold=5,
    window_seconds=60
)

risk_engine = RiskEngine()

alert_manager = AlertManager()

deduplicator = AlertDeduplicator(
    cooldown_seconds=30
)


def process_log_line(line):

    event = parser.parse_line(line)

    if not event:
        return

    detection = detector.detect(event)

    if not detection:
        return

    features = {
        "unique_destination_ports": 0,
        "syn_count": 0,
        "total_packets": detection["failed_attempts"],
        "window_seconds": detection["window_seconds"]
    }

    risk = risk_engine.calculate(
         features,
         detection["detection"]
   )
    alert = {
        "event_type": detection["detection"],
        "source_ip": detection["source_ip"],
        "destination_ip": "SSH Server",
        "severity": risk["severity"],
        "confidence": risk["risk_score"],
        "risk_score": risk["risk_score"],
        "failed_attempts": detection["failed_attempts"],
        "window_seconds": detection["window_seconds"],
        "reasons": [
            "Repeated authentication failures",
            "Multiple failures from the same source"
        ]
    }

    if deduplicator.should_alert(alert):

        alert_manager.save_alert(alert)

        print(
            f"[+] Brute Force Alert | "
            f"Risk: {risk['risk_score']} | "
            f"Severity: {risk['severity']}"
        )

    else:

        print("[*] Duplicate brute force alert suppressed")


def monitor_log():

    print(f"[*] Monitoring log file: {LOG_FILE}")

    with open(LOG_FILE, "r") as file:

        file.seek(0, 2)

        while True:

            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            process_log_line(line)


if __name__ == "__main__":
    monitor_log()
