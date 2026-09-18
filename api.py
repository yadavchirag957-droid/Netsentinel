from collections import Counter
import os
import tempfile

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    UploadFile,
    File
)
from fastapi.middleware.cors import CORSMiddleware

from alert_manager import AlertManager
from alert_pipeline import AlertPipeline
from detection_engine import DetectionEngine

from detectors.port_scan import PortScanDetector
from detectors.icmp_anomaly import ICMPAnomalyDetector
from detectors.dns_anomaly import DNSAnomalyDetector
from detectors.dos_anomaly import DoSAnomalyDetector

from pcap_analyzer import PCAPAnalyzer
from features import FeatureExtractor
from traffic_manager import TrafficManager
replay_feature_extractor = FeatureExtractor()


app = FastAPI(
    title="NetSentinel API",
    description="SOC-oriented network threat detection API",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Core Components
# ============================================================

alert_manager = AlertManager()
traffic_manager = TrafficManager()


detectors = [
    PortScanDetector(
        port_threshold=10,
        syn_threshold=5
    ),

    ICMPAnomalyDetector(
        packet_threshold=5,
        window_seconds=10
    ),

    DNSAnomalyDetector(
        query_threshold=30,
        window_seconds=10
    ),

    DoSAnomalyDetector(
        packet_threshold=100,
        window_seconds=10
    )
]


detection_engine = DetectionEngine(
    detectors=detectors
)


pcap_analyzer = PCAPAnalyzer(
    detection_engine=detection_engine
)


alert_pipeline = AlertPipeline()


# ============================================================
# Basic Endpoints
# ============================================================

@app.get("/")
def root():

    return {
        "name": "NetSentinel",
        "status": "online",
        "version": "1.0.0"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# Alert Endpoints
# ============================================================

@app.get("/alerts")
def get_alerts(
    severity: str | None = Query(
        default=None
    ),
    detection: str | None = Query(
        default=None
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500
    )
):

    alerts = alert_manager.get_alerts()

    if severity:

        alerts = [
            alert
            for alert in alerts
            if alert.get(
                "severity",
                ""
            ).lower() == severity.lower()
        ]

    if detection:

        alerts = [
            alert
            for alert in alerts
            if detection.lower()
            in alert.get(
                "detection",
                ""
            ).lower()
        ]

    alerts = alerts[-limit:]

    return {
        "count": len(alerts),
        "alerts": alerts
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):

    alerts = alert_manager.get_alerts()

    for alert in alerts:

        if alert.get("id") == alert_id:
            return alert

    raise HTTPException(
        status_code=404,
        detail="Alert not found"
    )


# ============================================================
# Statistics Endpoint
# ============================================================

@app.get("/statistics")
def get_statistics():

    alerts = alert_manager.get_alerts()

    severity_counts = Counter(
        alert.get(
            "severity",
            "Unknown"
        )
        for alert in alerts
    )

    detection_counts = Counter(
        alert.get(
            "detection",
            "Unknown"
        )
        for alert in alerts
    )

    return {
        "total_alerts": len(alerts),
        "severity": dict(severity_counts),
        "detections": dict(detection_counts)
    }


# ============================================================
# Events Endpoint
# ============================================================

@app.get("/events")
def get_events(
    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    alerts = alert_manager.get_alerts()

    recent = alerts[-limit:]

    events = []

    for alert in recent:

        events.append({
            "id": alert.get("id"),
            "timestamp": alert.get(
                "timestamp"
            ),
            "detection": alert.get(
                "detection"
            ),
            "source_ip": alert.get(
                "source_ip"
            ),
            "destination_ip": alert.get(
                "destination_ip"
            ),
            "severity": alert.get(
                "severity"
            ),
            "risk_score": alert.get(
                "risk_score"
            ),
            "status": alert.get(
                "status"
            )
        })

    return {
        "count": len(events),
        "events": events
    }


# ============================================================
# Traffic Endpoint
# ============================================================

@app.get("/traffic")
def get_traffic():

    alerts = alert_manager.get_alerts()

    sources = Counter()
    destinations = Counter()
    protocols = Counter()

    for alert in alerts:

        source = alert.get(
            "source_ip"
        )

        destination = alert.get(
            "destination_ip"
        )

        protocol = alert.get(
            "protocol"
        )

        if source:
            sources[source] += 1

        if destination:
            destinations[destination] += 1

        if protocol:
            protocols[protocol] += 1

    return {
        "total_security_events": len(alerts),
        "top_sources": dict(
            sources.most_common(10)
        ),
        "top_destinations": dict(
            destinations.most_common(10)
        ),
        "protocols": dict(protocols)
    }


# ============================================================
# PCAP Analysis Endpoint
# ============================================================

@app.post("/analyze-pcap")
async def analyze_pcap(
    file: UploadFile = File(...)
):

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file provided"
        )

    if not file.filename.lower().endswith(".pcap"):

        raise HTTPException(
            status_code=400,
            detail="Only .pcap files are supported"
        )

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pcap"
        ) as temp_file:

            temp_path = temp_file.name

            content = await file.read()

            temp_file.write(content)

        detections = pcap_analyzer.analyze(
            temp_path
        )

        alerts = []

        for result in detections:

            detection = result["detection"]

            features = result["features"]

            alert = alert_pipeline.process_detection(
                detection=detection,
                features=features
            )

            if alert is not None:

                alerts.append(alert)

        return {
            "filename": file.filename,
            "detections": len(detections),
            "results": detections,
            "alerts": alerts
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {error}"
        )

    finally:

        if temp_path and os.path.exists(temp_path):

            os.remove(temp_path)


@app.post("/traffic/replay")
def replay_traffic(event: dict):

    normalized_event = {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("source_ip"),
        "dst_ip": event.get("destination_ip"),
        "protocol": event.get("protocol", "OTHER"),
        "src_port": None,
        "dst_port": (
            int(event["destination_port"])
            if event.get("destination_port") not in ("", None)
            else None
        ),
        "tcp_flags": "S" if event.get("event_type") == "Port Scan" else ("A" if event.get("protocol") == "TCP" else None),
    }

    traffic_manager.add_event(event)

    replay_feature_extractor.add_event(normalized_event)

    features = replay_feature_extractor.get_features(
        normalized_event["src_ip"],
        normalized_event["dst_ip"],
        window_seconds=10
    )

    detections = detection_engine.detect(
        event=normalized_event,
        features=features
    )

    alerts = []

    for detection in detections:

        alert = alert_pipeline.process_detection(
            detection=detection,
            features=features
        )

        if alert is not None:
            alerts.append(alert)

    return {
        "status": "accepted",
        "event": event,
        "detections": len(detections),
        "alerts": alerts
    }


@app.get("/traffic/live")
def get_live_traffic(limit: int = Query(default=500, ge=1, le=5000)):
    return {
        "count": traffic_manager.get_statistics()["total_events"],
        "events": traffic_manager.get_events(limit),
        "statistics": traffic_manager.get_statistics()
    }
