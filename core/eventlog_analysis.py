from core.gap_detection import find_timeline_gaps

# Event IDs we care about, with human-readable meaning
LOG_CLEARED_EVENT_ID = 1102
AUDIT_POLICY_CHANGED_EVENT_ID = 4719

# If the gap between two consecutive events exceeds this,
# we consider it suspicious (30 minutes, adjustable later)
GAP_THRESHOLD_MINUTES = 30


def analyze_event_log(events):
    """
    Analyzes a list of event dictionaries for anti-forensic indicators.
    """
    indicators = []

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

    # Check 2: Use our SHARED gap-detection function
    gap_indicators = find_timeline_gaps(
        sorted_events,
        threshold_minutes=GAP_THRESHOLD_MINUTES,
        timestamp_key="timestamp"
    )
    indicators.extend(gap_indicators)

    return {
        "indicators": indicators,
        "anomaly_detected": len(indicators) > 0
    }