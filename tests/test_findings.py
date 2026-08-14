import sys
import os
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.risk_scoring import calculate_risk_score
from core.timestamp_analysis import analyze_timestamps
from core.eventlog_analysis import analyze_event_log
from core.findings import build_findings_from_risk_result

# Reuse our known suspicious scenario
anomaly_file = os.path.join(project_root, "evidence", "input", "anomaly_test.txt")
timestamp_result = analyze_timestamps(anomaly_file)

suspicious_events = [
    {"event_id": 4719, "timestamp": datetime(2026, 8, 2, 9, 5, 0), "source": "Security", "message": "Audit policy changed"},
    {"event_id": 1102, "timestamp": datetime(2026, 8, 2, 9, 6, 0), "source": "Security", "message": "The audit log was cleared"},
]
eventlog_result = analyze_event_log(suspicious_events)

risk_result = calculate_risk_score(timestamp_result=timestamp_result, eventlog_result=eventlog_result)

findings = build_findings_from_risk_result(risk_result, evidence_reference="anomaly_test.txt")

print(f"Total findings generated: {len(findings)}")
print()
for f in findings:
    print(f"Finding ID: {f['finding_id']}")
    print(f"  Type:     {f['type']}")
    print(f"  Severity: {f['severity']}")
    print(f"  Evidence: {f['evidence']}")
    print(f"  Reason:   {f['reason']}")
    print()