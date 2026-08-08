import sys
import os
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.risk_scoring import calculate_risk_score
from core.timestamp_analysis import analyze_timestamps
from core.eventlog_analysis import analyze_event_log
from core.browser_analysis import analyze_browser_history

# Test Case 1: Clean evidence - no anomalies anywhere
clean_timestamp_result = {"anomaly_detected": False, "explanation": "No timestamp inconsistency detected."}
clean_eventlog_result = {"anomaly_detected": False, "indicators": []}
clean_browser_result = {"anomaly_detected": False, "indicators": []}

result = calculate_risk_score(clean_timestamp_result, clean_eventlog_result, clean_browser_result)
print("Test 1 - Clean evidence (all 3 modules):")
print("  Score:", result["score"])
print("  Risk Level:", result["risk_level"])
print()

# Test Case 2: Suspicious evidence across ALL THREE modules
anomaly_file = os.path.join(project_root, "evidence", "input", "anomaly_test.txt")
timestamp_result = analyze_timestamps(anomaly_file)

suspicious_events = [
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 0, 0), "source": "Security", "message": "Successful logon"},
    {"event_id": 4719, "timestamp": datetime(2026, 8, 2, 9, 5, 0), "source": "Security", "message": "Audit policy changed"},
    {"event_id": 1102, "timestamp": datetime(2026, 8, 2, 9, 6, 0), "source": "Security", "message": "The audit log was cleared"},
    {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 51, 0), "source": "Security", "message": "Successful logon"},
]
eventlog_result = analyze_event_log(suspicious_events)

suspicious_visits = [
    {"url": "https://example.com", "title": "Example", "visit_time": datetime(2026, 8, 2, 14, 0, 0)},
    {"url": "https://news.com", "title": "News", "visit_time": datetime(2026, 8, 2, 14, 5, 0)},
    {"url": "https://shopping.com", "title": "Shopping", "visit_time": datetime(2026, 8, 2, 14, 45, 0)},
]
browser_result = analyze_browser_history(suspicious_visits)

result = calculate_risk_score(timestamp_result, eventlog_result, browser_result)
print("Test 2 - Suspicious evidence (all 3 modules triggered):")
print("  Score:", result["score"])
print("  Risk Level:", result["risk_level"])
print("  Contributing indicators:")
for ind in result["contributing_indicators"]:
    print(f"    - {ind['type']}: +{ind['points']}")