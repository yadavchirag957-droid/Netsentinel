import uuid
from datetime import datetime, timezone


def build_alert(
    detection,
    source_ip=None,
    destination_ip=None,
    severity="Low",
    risk_score=0,
    confidence=0,
    evidence=None,
    protocol=None
):
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection": detection,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "status": "New",
        "evidence": evidence or {}
    }
