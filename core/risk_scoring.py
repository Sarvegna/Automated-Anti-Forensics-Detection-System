INDICATOR_WEIGHTS = {
    "Modified Before Created": 20,
    "Accessed Before Created": 20,
    "Future Timestamp": 25,
    "Accessed Before Modified": 10,
    "Log Cleared": 25,
    "Audit Policy Changed": 20,
    "Timeline Gap": 15,
    "Hidden File": 10,
}

MAX_SCORE = 100


def calculate_risk_score(timestamp_result=None, eventlog_result=None, browser_result=None, hidden_file_result=None):
    """
    Combines findings from timestamp, event log, browser, and hidden
    file analysis into a single explainable risk score.
    """
    contributing_indicators = []
    total_score = 0

    # Timestamp analysis now returns MULTIPLE indicators (like eventlog/browser)
    if timestamp_result and timestamp_result.get("anomaly_detected"):
        for indicator in timestamp_result["indicators"]:
            indicator_type = indicator["type"]
            points = INDICATOR_WEIGHTS.get(indicator_type, 0)
            total_score += points
            contributing_indicators.append({
                "type": f"{indicator_type} (Timestamp)",
                "points": points,
                "explanation": indicator.get("explanation")
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

    if hidden_file_result and hidden_file_result.get("anomaly_detected"):
        points = INDICATOR_WEIGHTS["Hidden File"]
        total_score += points
        contributing_indicators.append({
            "type": "Hidden File",
            "points": points,
            "explanation": hidden_file_result.get("explanation")
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