import sys
import os
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.eventlog_analysis import analyze_event_log

# Test Case 1: Normal event log — no anomalies
normal_events = [
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 0, 0), "source": "Security", "message": "Successful logon"},
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 5, 0), "source": "Security", "message": "Successful logon"},
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 10, 0), "source": "Security", "message": "Successful logon"},
]

result = analyze_event_log(normal_events)
print("Test 1 - Normal log:")
print("  Anomaly detected:", result["anomaly_detected"])
print("  Indicators found:", len(result["indicators"]))
print()

# Test Case 2: Suspicious event log — contains 1102, 4719, and a timeline gap
suspicious_events = [
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 0, 0), "source": "Security", "message": "Successful logon"},
    {"event_id": 4719, "timestamp": datetime(2026, 8, 2, 9, 5, 0), "source": "Security", "message": "Audit policy changed"},
    {"event_id": 1102, "timestamp": datetime(2026, 8, 2, 9, 6, 0), "source": "Security", "message": "The audit log was cleared"},
    # Big gap here - next event is 45 minutes later
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 51, 0), "source": "Security", "message": "Successful logon"},
]

result = analyze_event_log(suspicious_events)
print("Test 2 - Suspicious log:")
print("  Anomaly detected:", result["anomaly_detected"])
print("  Indicators found:", len(result["indicators"]))
for indicator in result["indicators"]:
    print("   -", indicator["type"], ":", indicator["explanation"])