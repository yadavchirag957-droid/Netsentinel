class RiskEngine:

    def calculate(self, features, detection_type=None):

        score = 0
        reasons = []

        unique_ports = features.get("unique_destination_ports", 0)
        syn_count = features.get("syn_count", 0)
        total_packets = features.get("total_packets", 0)
        window = features.get("window_seconds", 10)

        failed_attempts = features.get("failed_attempts", 0)
        query_count = features.get("query_count", 0)
        packet_count = features.get("packet_count", 0)

        # =====================================================
        # Port Scan Detection
        # =====================================================

        if detection_type == "Possible Port Scan":

            if unique_ports >= 10:
                score += 40
                reasons.append(
                    "High number of unique destination ports"
                )

            if syn_count >= 5:
                score += 30
                reasons.append(
                    "High number of TCP SYN packets"
                )

            if window <= 5:
                score += 20
                reasons.append(
                    "Activity occurred within a short time window"
                )

            if total_packets >= 20:
                score += 10
                reasons.append(
                    "High packet volume"
                )

        # =====================================================
        # ICMP Anomaly / Flood
        # =====================================================

        elif detection_type == "Possible ICMP Flood/Anomaly":

            if packet_count >= 50:
                score += 60
                reasons.append(
                    "High volume of ICMP packets"
                )

            if window <= 10:
                score += 20
                reasons.append(
                    "ICMP activity occurred within a short time window"
                )

            if packet_count >= 100:
                score += 20
                reasons.append(
                    "Very high ICMP packet volume"
                )

        # =====================================================
        # DNS Query Anomaly
        # =====================================================

        elif detection_type == "Possible DNS Query Anomaly":

            if query_count >= 30:
                score += 60
                reasons.append(
                    "High number of DNS queries"
                )

            if window <= 10:
                score += 20
                reasons.append(
                    "DNS activity occurred within a short time window"
                )

            if query_count >= 60:
                score += 20
                reasons.append(
                    "Very high DNS query volume"
                )

        # =====================================================
        # DoS-like Traffic
        # =====================================================

        elif detection_type == "Possible DoS-like Traffic":

            if packet_count >= 100:
                score += 60
                reasons.append(
                    "High packet volume from the same source"
                )

            if window <= 10:
                score += 20
                reasons.append(
                    "High traffic occurred within a short time window"
                )

            if packet_count >= 200:
                score += 20
                reasons.append(
                    "Very high packet volume"
                )

        # =====================================================
        # SSH Brute Force
        # =====================================================

        elif detection_type == "Possible SSH Brute Force":

            if failed_attempts >= 5:
                score += 50
                reasons.append(
                    "Repeated authentication failures"
                )

            if failed_attempts >= 10:
                score += 30
                reasons.append(
                    "High number of failed authentication attempts"
                )

            if window <= 60:
                score += 20
                reasons.append(
                    "Authentication failures occurred within a short time window"
                )

        # =====================================================
        # Generic Network Behaviour
        # =====================================================

        else:

            if unique_ports >= 10:
                score += 40
                reasons.append(
                    "High number of unique destination ports"
                )

            if syn_count >= 5:
                score += 30
                reasons.append(
                    "High number of TCP SYN packets"
                )

            if total_packets >= 20:
                score += 10
                reasons.append(
                    "High packet volume"
                )

        # Keep score within 0-100
        score = min(score, 100)

        # =====================================================
        # Detection-aware Severity
        # =====================================================

        if detection_type == "Possible ICMP Flood/Anomaly":
            severity = "CRITICAL"
            score = max(score, 80)

        elif detection_type == "Possible DoS-like Traffic":
            severity = "CRITICAL"
            score = max(score, 80)

        elif detection_type == "Possible Port Scan":
            severity = "HIGH"
            score = max(score, 60)

        elif detection_type == "Possible DNS Query Anomaly":
            severity = "MEDIUM"
            score = max(score, 40)

        elif score >= 80:
            severity = "CRITICAL"

        elif score >= 60:
            severity = "HIGH"

        elif score >= 30:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }
