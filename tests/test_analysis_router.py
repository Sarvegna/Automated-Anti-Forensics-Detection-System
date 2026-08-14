import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.analysis_router import run_automated_analysis

# Test Case 1: Generic file (should run ONLY general checks)
generic_file = os.path.join(project_root, "evidence", "input", "sample_evidence.txt")
result = run_automated_analysis(generic_file)
print("Test 1 - Generic file (.txt):")
print("  Identified as:", result["identification"]["evidence_type"])
print("  Modules run:", result["modules_run"])
print("  Event log result:", result["eventlog_result"])
print()

# Test Case 2: Real .evtx file (should run general checks + Event Log Analysis)
evtx_file = os.path.join(project_root, "evidence", "input", "UACME_59_Sysmon.evtx")
result = run_automated_analysis(evtx_file)
print("Test 2 - Real Windows Event Log (.evtx):")
print("  Identified as:", result["identification"]["evidence_type"])
print("  Modules run:", result["modules_run"])
print("  Event log anomaly detected:", result["eventlog_result"]["anomaly_detected"])
print("  Event log indicators found:", len(result["eventlog_result"]["indicators"]))