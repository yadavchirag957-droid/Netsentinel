import csv
import time
import requests


DATASET_FILE = "traffic_generator/traffic_dataset.csv"
API_URL = "http://127.0.0.1:8000/traffic/replay"


def replay_dataset(delay=0.05):

    print("[*] Starting NetSentinel traffic replay...")
    print(f"[*] Dataset: {DATASET_FILE}")
    print(f"[*] Replay delay: {delay}s")

    with open(DATASET_FILE, "r", newline="") as file:

        reader = csv.DictReader(file)

        for event in reader:

            try:
                response = requests.post(
                    API_URL,
                    json=event,
                    timeout=2
                )

                if response.status_code != 200:
                    print(
                        f"[!] Backend rejected event: "
                        f"{response.status_code}"
                    )

            except requests.RequestException as error:
                print(f"[!] Backend connection error: {error}")
                break

            time.sleep(delay)

    print("[+] Traffic replay completed.")


if __name__ == "__main__":
    replay_dataset()
