import os
from datetime import datetime


def analyze_timestamps(file_path):
    """
    Reads a file's Created, Modified, and Accessed timestamps, and
    checks for multiple timestamp consistency anomalies - each
    reported as a SEPARATE, individually named indicator for
    investigator traceability .

    Returns a dictionary containing:
    - created, modified, accessed: human-readable timestamps
    - indicators: list of individual anomaly findings
    - anomaly_detected: True/False (True if ANY indicator fired)
    """
    created_raw = os.path.getctime(file_path)
    modified_raw = os.path.getmtime(file_path)
    accessed_raw = os.path.getatime(file_path)

    created = datetime.fromtimestamp(created_raw)
    modified = datetime.fromtimestamp(modified_raw)
    accessed = datetime.fromtimestamp(accessed_raw)

    now = datetime.now()
    indicators = []

    # Check 1: Modified < Created (logical impossibility)
    if modified < created:
        indicators.append({
            "type": "Modified Before Created",
            "explanation": (
                "Potential anti-forensic indicator: Modified time is "
                "earlier than Created time. This is not possible under "
                "normal file system behavior and requires investigator "
                "review."
            )
        })

    # Check 2: Accessed < Created (logical impossibility)
    if accessed < created:
        indicators.append({
            "type": "Accessed Before Created",
            "explanation": (
                "Potential anti-forensic indicator: Accessed time is "
                "earlier than Created time. A file cannot be accessed "
                "before it exists under normal file system behavior; "
                "requires investigator review."
            )
        })

    # Check 3: Future timestamps (any of the three ahead of "now")
    if created > now or modified > now or accessed > now:
        indicators.append({
            "type": "Future Timestamp",
            "explanation": (
                "Potential anti-forensic indicator: one or more "
                "timestamps are set in the future relative to the "
                "current system time. This may indicate deliberate "
                "timestamp manipulation or a system clock error; "
                "requires investigator review."
            )
        })

    # Check 4: Accessed significantly before Modified (weaker signal)
    if accessed < modified:
        indicators.append({
            "type": "Accessed Before Modified",
            "explanation": (
                "Observation: Accessed time is earlier than Modified "
                "time. This is a weaker, more ambiguous signal than "
                "other timestamp checks, as legitimate scenarios can "
                "produce this pattern; combine with other indicators "
                "before treating as significant."
            )
        })

    return {
        "file_path": file_path,
        "created": created,
        "modified": modified,
        "accessed": accessed,
        "indicators": indicators,
        "anomaly_detected": len(indicators) > 0
    }