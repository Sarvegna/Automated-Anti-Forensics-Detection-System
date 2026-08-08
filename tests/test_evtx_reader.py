import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.evtx_reader import read_evtx_file
from core.eventlog_analysis import analyze_event_log

file_path = os.path.join(project_root, "evidence", "input", "UACME_59_Sysmon.evtx")

# Step 1: Read the real file
events = read_evtx_file(file_path)
print(f"Total events extracted: {len(events)}")
print("First 3 events:")
for e in events[:3]:
    print(" ", e)
print()

# Step 2: Run our EXISTING, already-tested detection logic on this REAL data
result = analyze_event_log(events)
print("Anomaly detected:", result["anomaly_detected"])
print("Indicators found:", len(result["indicators"]))
for indicator in result["indicators"][:5]:
    print(" -", indicator["type"], ":", indicator.get("explanation", ""))