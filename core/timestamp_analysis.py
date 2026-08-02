import os
from datetime import datetime

def analyze_timestamps(file_path):
    """
    Reads a file's Created, Modified, and Accessed timestamps,
    and checks for a specific anti-forensic indicator:
    Modified time earlier than Created time (logically impossible
    under normal file system behavior).

    Returns a dictionary containing:
    - created, modified, accessed: human-readable timestamps
    - anomaly_detected: True/False
    - explanation: description of the finding
    """
    created_raw = os.path.getctime(file_path)
    modified_raw = os.path.getmtime(file_path)
    accessed_raw = os.path.getatime(file_path)

    created = datetime.fromtimestamp(created_raw)
    modified = datetime.fromtimestamp(modified_raw)
    accessed = datetime.fromtimestamp(accessed_raw)

    anomaly_detected = False
    explanation = "No timestamp inconsistency detected."

    if modified < created:
        anomaly_detected = True
        explanation = (
            "Potential anti-forensic indicator: Modified time is earlier "
            "than Created time. This is not possible under normal file "
            "system behavior and requires investigator review."
        )

    return {
        "file_path": file_path,
        "created": created,
        "modified": modified,
        "accessed": accessed,
        "anomaly_detected": anomaly_detected,
        "explanation": explanation
    }