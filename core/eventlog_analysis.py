from datetime import timedelta

# Event IDs we care about, with human-readable meaning
LOG_CLEARED_EVENT_ID = 1102
AUDIT_POLICY_CHANGED_EVENT_ID = 4719

# If the gap between two consecutive events exceeds this,
# we consider it suspicious (30 minutes, adjustable later)
GAP_THRESHOLD_MINUTES = 30


def analyze_event_log(events):
    """
    Analyzes a list of event dictionaries for anti-forensic indicators.

    Each event dictionary must have:
        - event_id (int)
        - timestamp (datetime)
        - source (str)
        - message (str)

    Returns a dictionary with:
        - indicators: list of specific findings
        - anomaly_detected: True/False
    """
    indicators = []

    # Sort events chronologically, just in case they weren't already
    sorted_events = sorted(events, key=lambda e: e["timestamp"])

    # Check 1: Look for log-cleared or audit-policy-changed events
    for event in sorted_events:
        if event["event_id"] == LOG_CLEARED_EVENT_ID:
            indicators.append({
                "type": "Log Cleared",
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "explanation": (
                    "Potential anti-forensic indicator: audit log was "
                    "cleared. Requires investigator review."
                )
            })

        if event["event_id"] == AUDIT_POLICY_CHANGED_EVENT_ID:
            indicators.append({
                "type": "Audit Policy Changed",
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "explanation": (
                    "Potential anti-forensic indicator: audit policy was "
                    "modified, which may reduce future logging. Requires "
                    "investigator review."
                )
            })

    # Check 2: Look for suspicious time gaps between consecutive events
    for i in range(len(sorted_events) - 1):
        current_event = sorted_events[i]
        next_event = sorted_events[i + 1]

        gap = next_event["timestamp"] - current_event["timestamp"]

        if gap > timedelta(minutes=GAP_THRESHOLD_MINUTES):
            indicators.append({
                "type": "Timeline Gap",
                "gap_minutes": gap.total_seconds() / 60,
                "between": (current_event["timestamp"], next_event["timestamp"]),
                "explanation": (
                    f"Potential anti-forensic indicator: a gap of "
                    f"{gap.total_seconds() / 60:.1f} minutes was found "
                    f"between consecutive log entries. This may indicate "
                    f"missing or deleted events. Requires investigator review."
                )
            })

    return {
        "indicators": indicators,
        "anomaly_detected": len(indicators) > 0
    }