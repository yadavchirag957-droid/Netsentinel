from alert_schema import build_alert
from risk_engine import RiskEngine
from alert_manager import AlertManager
from alert_deduplicator import AlertDeduplicator


class AlertPipeline:

    def __init__(self):

        self.risk_engine = RiskEngine()

        self.alert_manager = AlertManager()

        self.deduplicator = AlertDeduplicator(
            cooldown_seconds=30
        )

    def process_detection(
        self,
        detection,
        features=None
    ):

        features = features or {}

        detection_type = detection.get(
            "detection",
            "Unknown Detection"
        )

        risk = self.risk_engine.calculate(
            features,
            detection_type
        )

        alert = build_alert(

            detection=detection_type,

            source_ip=detection.get(
                "source_ip",
                features.get("source_ip")
            ),

            destination_ip=detection.get(
                "destination_ip",
                features.get("destination_ip")
            ),

            severity=risk.get(
                "severity",
                "LOW"
            ),

            risk_score=risk.get(
                "risk_score",
                0
            ),

            confidence=risk.get(
                "risk_score",
                0
            ),

            protocol=detection.get(
                "protocol",
                features.get("protocol")
            ),

            evidence=detection
        )

        if self.deduplicator.should_alert(alert):

            self.alert_manager.save_alert(
                alert
            )

            return alert

        return None
