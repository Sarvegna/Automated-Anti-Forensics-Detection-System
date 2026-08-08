INDICATOR_WEIGHTS = {
    "Timestamp Anomaly": 20,
    "Log Cleared": 25,
    "Audit Policy Changed": 20,
    "Timeline Gap": 15,
}

MAX_SCORE = 100


def calculate_risk_score(timestamp_result=None, eventlog_result=None, browser_result=None):
    """
    Combines findings from timestamp, event log, and browser analysis
    into a single explainable risk score.
    """
    contributing_indicators = []
    total_score = 0

    if timestamp_result and timestamp_result.get("anomaly_detected"):
        points = INDICATOR_WEIGHTS["Timestamp Anomaly"]
        total_score += points
        contributing_indicators.append({
            "type": "Timestamp Anomaly",
            "points": points,
            "explanation": timestamp_result.get("explanation")
        })

    if eventlog_result and eventlog_result.get("anomaly_detected"):
        for indicator in eventlog_result["indicators"]:
            indicator_type = indicator["type"]
            points = INDICATOR_WEIGHTS.get(indicator_type, 0)
            total_score += points
            contributing_indicators.append({
                "type": f"{indicator_type} (Event Log)",
                "points": points,
                "explanation": indicator.get("explanation")
            })

    if browser_result and browser_result.get("anomaly_detected"):
        for indicator in browser_result["indicators"]:
            indicator_type = indicator["type"]
            points = INDICATOR_WEIGHTS.get(indicator_type, 0)
            total_score += points
            contributing_indicators.append({
                "type": f"{indicator_type} (Browser)",
                "points": points,
                "explanation": indicator.get("explanation")
            })

    total_score = min(total_score, MAX_SCORE)

    if total_score >= 60:
        risk_level = "HIGH"
    elif total_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": total_score,
        "risk_level": risk_level,
        "contributing_indicators": contributing_indicators
    }