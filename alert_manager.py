import json


class AlertManager:

    def __init__(self, log_file="alerts.jsonl"):
        self.log_file = log_file

    def save_alert(self, alert):

        with open(self.log_file, "a") as file:
            file.write(
                json.dumps(alert) + "\n"
            )

    def get_alerts(self):

        alerts = []

        try:

            with open(self.log_file, "r") as file:

                for line in file:

                    line = line.strip()

                    if line:
                        alerts.append(
                            json.loads(line)
                        )

        except FileNotFoundError:

            return []

        return alerts
