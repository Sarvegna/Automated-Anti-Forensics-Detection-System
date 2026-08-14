import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.analysis_router import run_automated_analysis

# Test Case 1: Generic file (general checks only)
generic_file = os.path.join(project_root, "evidence", "input", "sample_evidence.txt")
result = run_automated_analysis(generic_file)
print("Test 1 - Generic file (.txt):")
print("  Identified as:", result["identification"]["evidence_type"])
print("  Modules run:", result["modules_run"])
print("  Risk Score:", result["risk_result"]["score"], "/", result["risk_result"]["risk_level"])
print("  Findings generated:", len(result["findings"]))
print()

# Test Case 2: Real .evtx file (full pipeline including event log)
evtx_file = os.path.join(project_root, "evidence", "input", "UACME_59_Sysmon.evtx")
result = run_automated_analysis(evtx_file)
print("Test 2 - Real Windows Event Log (.evtx):")
print("  Identified as:", result["identification"]["evidence_type"])
print("  Modules run:", result["modules_run"])
print("  Risk Score:", result["risk_result"]["score"], "/", result["risk_result"]["risk_level"])
print("  Findings generated:", len(result["findings"]))
print()

# Test Case 3: Our known anomalous file (should produce actual findings)
anomaly_file = os.path.join(project_root, "evidence", "input", "anomaly_test.txt")
result = run_automated_analysis(anomaly_file)
print("Test 3 - Known anomalous file:")
print("  Identified as:", result["identification"]["evidence_type"])
print("  Modules run:", result["modules_run"])
print("  Risk Score:", result["risk_result"]["score"], "/", result["risk_result"]["risk_level"])
print("  Findings generated:", len(result["findings"]))
for f in result["findings"]:
    print(f"    - [{f['finding_id']}] {f['type']} ({f['severity']})")