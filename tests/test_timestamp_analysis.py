import sys
import os
import time
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.timestamp_analysis import analyze_timestamps

# Test Case 1: Normal file (our existing synthetic evidence)
normal_file = os.path.join(project_root, "evidence", "input", "sample_evidence.txt")
result = analyze_timestamps(normal_file)
print("Test 1 - Normal file:")
print("  Anomaly detected:", result["anomaly_detected"])
print("  Explanation:", result["explanation"])
print()

# Test Case 2: Create a file, then manually set Modified time
# to BEFORE the current time, simulating a timestomping scenario
anomaly_file = os.path.join(project_root, "evidence", "input", "anomaly_test.txt")
with open(anomaly_file, "w") as f:
    f.write("Synthetic file for timestamp anomaly testing.")

# Set modified time to 10 days in the past (created time stays "now")
past_time = time.time() - (10 * 24 * 60 * 60)  # 10 days ago, in seconds
os.utime(anomaly_file, (past_time, past_time))  # (access_time, modified_time)

result = analyze_timestamps(anomaly_file)
print("Test 2 - Anomalous file (Modified set 10 days in the past):")
print("  Created:", result["created"])
print("  Modified:", result["modified"])
print("  Anomaly detected:", result["anomaly_detected"])
print("  Explanation:", result["explanation"])