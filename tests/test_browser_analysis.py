import sys
import os
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.browser_analysis import analyze_browser_history

# Test Case 1: Normal browsing - no gaps
normal_visits = [
    {"url": "https://example.com", "title": "Example", "visit_time": datetime(2026, 8, 2, 14, 0, 0)},
    {"url": "https://news.com", "title": "News", "visit_time": datetime(2026, 8, 2, 14, 5, 0)},
    {"url": "https://mail.com", "title": "Mail", "visit_time": datetime(2026, 8, 2, 14, 10, 0)},
]

result = analyze_browser_history(normal_visits)
print("Test 1 - Normal browsing:")
print("  Anomaly detected:", result["anomaly_detected"])
print("  Indicators found:", len(result["indicators"]))
print()

# Test Case 2: Suspicious browsing - 40 minute gap in the middle
suspicious_visits = [
    {"url": "https://example.com", "title": "Example", "visit_time": datetime(2026, 8, 2, 14, 0, 0)},
    {"url": "https://news.com", "title": "News", "visit_time": datetime(2026, 8, 2, 14, 5, 0)},
    # 40 minute gap here
    {"url": "https://shopping.com", "title": "Shopping", "visit_time": datetime(2026, 8, 2, 14, 45, 0)},
]

result = analyze_browser_history(suspicious_visits)
print("Test 2 - Suspicious browsing (40 min gap):")
print("  Anomaly detected:", result["anomaly_detected"])
print("  Indicators found:", len(result["indicators"]))
for indicator in result["indicators"]:
    print("   -", indicator["type"], ":", indicator["explanation"])