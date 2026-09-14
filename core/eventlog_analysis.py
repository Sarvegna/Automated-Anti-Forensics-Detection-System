from datetime import datetime

from core.gap_detection import find_timeline_gaps


# Important Windows Security Event IDs
LOG_CLEARED_EVENT_ID = 1102
AUDIT_POLICY_CHANGED_EVENT_ID = 4719
EVENT_LOG_SERVICE_SHUTDOWN_EVENT_ID = 1100

# Timeline gap threshold
GAP_THRESHOLD_MINUTES = 30


def analyze_event_log(events):
    """
    Analyze Windows Event Log records for potential anti-forensic
    indicators based strictly on actual numeric Event IDs:
      - Event ID 1102: Security audit log cleared (25 pts, HIGH)
      - Event ID 4719: Audit policy changed (20 pts, HIGH)
      - Event ID 1100: Windows Event Log service shut down (20 pts, HIGH)
      - Timeline Gaps > 30 minutes (15 pts, MEDIUM)

    Other Security events (e.g., 4624, 4672, 4798, 4907, 5379, 5799)
    are recorded as analyzed events but do not generate anti-forensic findings.

    Expected event structure:
        {
            "event_id": int,
            "record_id": int (optional),
            "channel": str (optional),
            "computer": str (optional),
            "timestamp": datetime,
            "source": str,
            "message": str
        }

    Returns:
        {
            "indicators": [...],
            "anomaly_detected": bool,
            "total_events_analyzed": int,
            "event_id_counts": dict
        }
    """

    if not events:
        return {
            "indicators": [],
            "anomaly_detected": False,
            "total_events_analyzed": 0,
            "event_id_counts": {}
        }

    indicators = []

    # ---------------------------------------------------------
    # 1. Validate events for event-specific analysis
    # ---------------------------------------------------------
    valid_events = []
    event_id_counts = {}

    for event in events:
        if not isinstance(event, dict):
            continue

        event_id = event.get("event_id")
        timestamp = event.get("timestamp")

        # Event ID must be an integer
        if not isinstance(event_id, int):
            continue

        # Timestamp must be a datetime
        if not isinstance(timestamp, datetime):
            continue

        valid_events.append(event)
        event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1

    # Sort chronologically
    sorted_events = sorted(
        valid_events,
        key=lambda event: event["timestamp"]
    )

    # ---------------------------------------------------------
    # 2. Detect important Windows Security events (Strict numeric matching)
    # ---------------------------------------------------------
    for event in sorted_events:
        event_id = event["event_id"]
        timestamp = event["timestamp"]
        record_id = event.get("record_id")
        channel = event.get("channel", "Security")
        computer = event.get("computer", "Unknown")
        source = event.get("source", "Unknown")
        message = event.get("message", "")
        event_data = event.get("event_data", {})

        # -----------------------------------------------------
        # Event ID 1102 - Security audit log cleared
        # -----------------------------------------------------
        if event_id == LOG_CLEARED_EVENT_ID:
            indicators.append({
                "type": "Log Cleared",
                "event_id": event_id,
                "record_id": record_id,
                "channel": channel,
                "computer": computer,
                "timestamp": timestamp,
                "source": source,
                "message": message,
                "event_data": event_data,
                "severity": "HIGH",
                "points": 25,
                "explanation": (
                    "Windows Security audit log was cleared. "
                    "This is a significant forensic indicator because "
                    "clearing the Security log can remove previously "
                    "recorded audit events. Investigator review is "
                    "required to determine context and responsible account."
                )
            })

        # -----------------------------------------------------
        # Event ID 4719 - Audit policy changed
        # -----------------------------------------------------
        elif event_id == AUDIT_POLICY_CHANGED_EVENT_ID:
            indicators.append({
                "type": "Audit Policy Changed",
                "event_id": event_id,
                "record_id": record_id,
                "channel": channel,
                "computer": computer,
                "timestamp": timestamp,
                "source": source,
                "message": message,
                "event_data": event_data,
                "severity": "HIGH",
                "points": 20,
                "explanation": (
                    "Windows audit policy was changed. A policy change "
                    "may affect what security activity is recorded. "
                    "Investigator review is required to determine what "
                    "policy changed, who changed it, and why."
                )
            })

        # -----------------------------------------------------
        # Event ID 1100 - Event Log service shutdown
        # -----------------------------------------------------
        elif event_id == EVENT_LOG_SERVICE_SHUTDOWN_EVENT_ID:
            indicators.append({
                "type": "Event Log Service Shutdown",
                "event_id": event_id,
                "record_id": record_id,
                "channel": channel,
                "computer": computer,
                "timestamp": timestamp,
                "source": source,
                "message": message,
                "event_data": event_data,
                "severity": "HIGH",
                "points": 20,
                "explanation": (
                    "The Windows Event Log service was shut down. "
                    "This may interrupt event collection and can be "
                    "relevant when investigating possible attempts to "
                    "suppress or disrupt forensic logging. Investigator "
                    "review is required to determine the reason for shutdown."
                )
            })

    # ---------------------------------------------------------
    # 3. Detect timeline gaps using the shared module
    # ---------------------------------------------------------
    gap_indicators = find_timeline_gaps(
        sorted_events,
        threshold_minutes=GAP_THRESHOLD_MINUTES,
        timestamp_key="timestamp"
    )

    # Add Event Log context and points to timeline findings
    for gap in gap_indicators:
        gap["severity"] = "MEDIUM"
        gap["source"] = "Windows Event Log"
        gap["points"] = 15

    indicators.extend(gap_indicators)

    # ---------------------------------------------------------
    # 4. Return standardized analysis result
    # ---------------------------------------------------------
    return {
        "indicators": indicators,
        "anomaly_detected": len(indicators) > 0,
        "total_events_analyzed": len(valid_events),
        "event_id_counts": event_id_counts
    }

