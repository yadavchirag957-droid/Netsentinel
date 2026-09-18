from risk_engine import RiskEngine


engine = RiskEngine()


features = {
    "unique_destination_ports": 15,
    "syn_count": 10,
    "total_packets": 25,
    "window_seconds": 5
}


result = engine.calculate(features)

print(result)
