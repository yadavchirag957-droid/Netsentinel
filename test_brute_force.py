from detectors.brute_force import BruteForceDetector


detector = BruteForceDetector(
    attempt_threshold=5,
    window_seconds=60
)


event = {
    "event_type": "authentication_failure",
    "username": "kali",
    "source_ip": "192.168.56.3"
}


for i in range(5):

    result = detector.detect(event)

    print(f"Attempt {i + 1}: {result}")
