import sys
import os
import time
import tempfile
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.timestamp_analysis import analyze_timestamps


def run_tests():
    test_dir = tempfile.mkdtemp()
    try:
        # Test Case 1: Genuinely Normal File (Created <= Modified <= Accessed)
        normal_file = os.path.join(test_dir, "normal_file.txt")
        with open(normal_file, "w") as f:
            f.write("Normal file for timestamp testing.")

        # Ensure modified and access timestamps are equal to or after creation time
        now = time.time()
        os.utime(normal_file, (now, now))

        res1 = analyze_timestamps(normal_file)
        print("==================================================")
        print("Test 1 - Normal file (Created <= Modified <= Accessed):")
        print("  Created :", res1["created"])
        print("  Modified:", res1["modified"])
        print("  Accessed:", res1["accessed"])
        print("  Anomaly detected:", res1["anomaly_detected"])
        print("  Indicators:", res1["indicators"])
        print("==================================================")

        assert not res1["anomaly_detected"], f"Test 1 failed: Expected no anomaly, got {res1['indicators']}"
        assert len(res1["indicators"]) == 0, f"Test 1 failed: Expected empty indicators, got {res1['indicators']}"

        # Test Case 2: Anomalous File (Modified set 10 days in the past relative to Created)
        anomaly_file = os.path.join(test_dir, "anomalous_past_file.txt")
        with open(anomaly_file, "w") as f:
            f.write("Anomalous file with past modified time.")

        past_time = time.time() - (10 * 24 * 60 * 60)  # 10 days in the past
        os.utime(anomaly_file, (past_time, past_time))

        res2 = analyze_timestamps(anomaly_file)
        print("\n==================================================")
        print("Test 2 - Anomalous file (Modified set 10 days in the past):")
        print("  Created :", res2["created"])
        print("  Modified:", res2["modified"])
        print("  Accessed:", res2["accessed"])
        print("  Anomaly detected:", res2["anomaly_detected"])
        print("  Indicators:")
        for ind in res2["indicators"]:
            print(f"    - {ind['type']}: {ind['explanation']}")
        print("==================================================")

        assert res2["anomaly_detected"], "Test 2 failed: Expected anomaly detected"
        ind_types_2 = [ind["type"] for ind in res2["indicators"]]
        assert "Modified Before Created" in ind_types_2, "Test 2 failed: Expected 'Modified Before Created' indicator"

        # Test Case 3: Anomalous File (Future Timestamp set 10 days in the future)
        future_file = os.path.join(test_dir, "anomalous_future_file.txt")
        with open(future_file, "w") as f:
            f.write("Anomalous file with future modified time.")

        future_time = time.time() + (10 * 24 * 60 * 60)  # 10 days in the future
        os.utime(future_file, (future_time, future_time))

        res3 = analyze_timestamps(future_file)
        print("\n==================================================")
        print("Test 3 - Anomalous file (Future timestamp set 10 days in the future):")
        print("  Created :", res3["created"])
        print("  Modified:", res3["modified"])
        print("  Accessed:", res3["accessed"])
        print("  Anomaly detected:", res3["anomaly_detected"])
        print("  Indicators:")
        for ind in res3["indicators"]:
            print(f"    - {ind['type']}: {ind['explanation']}")
        print("==================================================")

        assert res3["anomaly_detected"], "Test 3 failed: Expected anomaly detected"
        ind_types_3 = [ind["type"] for ind in res3["indicators"]]
        assert "Future Timestamp" in ind_types_3, "Test 3 failed: Expected 'Future Timestamp' indicator"

        print("\nALL TIMESTAMP ANALYSIS TESTS PASSED SUCCESSFULLY!")

    finally:
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    run_tests()