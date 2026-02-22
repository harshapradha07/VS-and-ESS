class RiskAnalyzer:
    def calculate_risk_score(self, scan_results, exploit_results):
        """
        Calculates a risk score from 0-100 and determines risk level.
        """
        base_score = 0
        vuln_count = 0
        critical_count = 0
        
        # Basic scoring logic
        for exploit in exploit_results:
            severity = exploit.get("severity", "Low")
            if severity == "High":
                base_score += 20
                critical_count += 1
            elif severity == "Medium":
                base_score += 10
            elif severity == "Low":
                base_score += 2
            
            vuln_count += 1

        # Cap at 100
        total_score = min(base_score, 100)
        
        # Ensure 0 score if no vulns
        if vuln_count == 0:
            total_score = 0

        # Determine Level
        if total_score >= 75:
            level = "CRITICAL"
            color = "red"
        elif total_score >= 50:
            level = "HIGH"
            color = "orange"
        elif total_score >= 25:
            level = "MEDIUM"
            color = "yellow"
        else:
            level = "LOW"
            color = "green"

        return {
            "score": total_score,
            "level": level,
            "color": color,
            "vuln_count": vuln_count,
            "critical_count": critical_count
        }
