from datetime import timedelta


def find_timeline_gaps(events, threshold_minutes, timestamp_key="timestamp"):
    """
    Generic function to detect suspicious time gaps between consecutive
    events, sorted chronologically.

    Parameters:
        events: list of dictionaries, each containing a timestamp field
        threshold_minutes: gap size (in minutes) above which we flag a gap
        timestamp_key: the dictionary key holding the timestamp
                       (allows reuse across different data structures,
                       e.g. "timestamp" for event logs, "visit_time" for browser)

    Returns a list of gap indicator dictionaries.
    """
    gap_indicators = []

    sorted_events = sorted(events, key=lambda e: e[timestamp_key])

    for i in range(len(sorted_events) - 1):
        current_event = sorted_events[i]
        next_event = sorted_events[i + 1]

        gap = next_event[timestamp_key] - current_event[timestamp_key]

        if gap > timedelta(minutes=threshold_minutes):
            gap_indicators.append({
                "type": "Timeline Gap",
                "gap_minutes": gap.total_seconds() / 60,
                "between": (current_event[timestamp_key], next_event[timestamp_key]),
                "explanation": (
                    f"Potential anti-forensic indicator: a gap of "
                    f"{gap.total_seconds() / 60:.1f} minutes was found "
                    f"between consecutive entries. This may indicate "
                    f"missing or deleted activity. Requires investigator review."
                )
            })

    return gap_indicators