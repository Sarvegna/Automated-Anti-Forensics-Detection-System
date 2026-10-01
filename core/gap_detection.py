from datetime import datetime, timedelta


def find_timeline_gaps(events, threshold_minutes, timestamp_key="timestamp"):
    """
    Detect timeline gaps between consecutive valid events.

    This is a shared utility used by:
        - Event Log Analysis
        - Browser Analysis

    Parameters:
        events: list of dictionaries containing timestamp information.
        threshold_minutes: gap size in minutes above which a gap is flagged.
        timestamp_key: dictionary key containing the timestamp.

    Returns:
        List of timeline gap indicator dictionaries.

    Notes:
        - Events with missing, None, or invalid timestamps are ignored.
        - Original event data is not modified.
        - A detected gap is reported as a potential timeline anomaly,
          not proof of anti-forensic activity.
    """

    if not events:
        return []

    valid_events = []

    # 1. Validate timestamps before sorting
    for event in events:
        if not isinstance(event, dict):
            continue

        timestamp = event.get(timestamp_key)

        if timestamp is None:
            continue

        if not isinstance(timestamp, datetime):
            continue

        valid_events.append(event)

    # Not enough valid events to calculate a gap
    if len(valid_events) < 2:
        return []

    # 2. Sort valid events chronologically
    sorted_events = sorted(
        valid_events,
        key=lambda e: e[timestamp_key]
    )

    gap_indicators = []

    # 3. Compare consecutive timestamps
    for i in range(len(sorted_events) - 1):

        current_event = sorted_events[i]
        next_event = sorted_events[i + 1]

        current_timestamp = current_event[timestamp_key]
        next_timestamp = next_event[timestamp_key]

        try:
            gap = next_timestamp - current_timestamp
        except (TypeError, ValueError):
            continue

        if gap > timedelta(minutes=threshold_minutes):

            gap_minutes = gap.total_seconds() / 60

            gap_item = {
                "type": "Timeline Gap",
                "gap_minutes": gap_minutes,
                "gap_duration_minutes": gap_minutes,
                "start_time": current_timestamp,
                "end_time": next_timestamp,
                "between": (
                    current_timestamp,
                    next_timestamp
                ),
                "from_record_id": current_event.get("record_id"),
                "to_record_id": next_event.get("record_id"),
                "from_event_id": current_event.get("event_id"),
                "to_event_id": next_event.get("event_id"),
                "explanation": (
                    f"Potential timeline anomaly: a gap of "
                    f"{gap_minutes:.1f} minutes was found between "
                    f"consecutive entries. This may indicate missing "
                    f"or unavailable activity. Requires investigator review."
                )
            }

            gap_indicators.append(gap_item)

    return gap_indicators

