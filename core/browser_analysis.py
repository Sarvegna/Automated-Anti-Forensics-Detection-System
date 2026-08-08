from core.gap_detection import find_timeline_gaps

# If the gap between two consecutive browser visits exceeds this,
# we consider it suspicious (30 minutes, same threshold as event logs)
GAP_THRESHOLD_MINUTES = 30


def analyze_browser_history(visits):
    """
    Analyzes a list of browser visit dictionaries for anti-forensic
    indicators - specifically, suspicious gaps in browsing activity.

    Each visit dictionary must have:
        - url (str)
        - title (str)
        - visit_time (datetime)

    Returns a dictionary with:
        - indicators: list of specific findings
        - anomaly_detected: True/False
    """
    sorted_visits = sorted(visits, key=lambda v: v["visit_time"])

    gap_indicators = find_timeline_gaps(
        sorted_visits,
        threshold_minutes=GAP_THRESHOLD_MINUTES,
        timestamp_key="visit_time"
    )

    return {
        "indicators": gap_indicators,
        "anomaly_detected": len(gap_indicators) > 0
    }