import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.analysis_router import run_automated_analysis


def test_future_timestamp_pipeline():
    print("==================================================")
    print("TESTING FUTURE TIMESTAMP LOCAL PATH PIPELINE")
    print("==================================================")

    test_file = os.path.join(project_root, "evidence", "input", "future_timestamp.txt")
    source_metadata = {
        "input_method": "local_path",
        "is_web_upload": False,
        "filename": "future_timestamp.txt"
    }

    res = run_automated_analysis(test_file, source_metadata=source_metadata)

    # 1. Timestamp Analysis = SUCCESS
    assert res["module_statuses"].get("Timestamp Analysis") == "SUCCESS"
    print("1. Timestamp Analysis Execution Status: SUCCESS")

    # 2. Future Timestamp finding = detected
    ts_res = res["timestamp_result"]
    assert ts_res["anomaly_detected"], "Expected timestamp anomaly to be detected"
    ind_types = [i["type"] for i in ts_res["indicators"]]
    assert "Future Timestamp" in ind_types, f"Expected 'Future Timestamp' in indicators, got {ind_types}"
    print("2. Future Timestamp Indicator Detected: True")

    # 3. Correct explanation displayed
    future_ind = next(i for i in ts_res["indicators"] if i["type"] == "Future Timestamp")
    exp = future_ind["explanation"]
    assert "in the future relative to the analysis reference time" in exp or "future relative to system clock" in exp or "future" in exp
    print("3. Explanation Displayed:")
    print("  ", exp)

    # 4. Risk Result & Severity = HIGH
    risk_res = res["risk_result"]
    assert risk_res["risk_level"] == "HIGH", f"Expected risk_level HIGH for score {risk_res['score']}, got {risk_res['risk_level']}"
    print(f"4. Aggregated Risk Score: {risk_res['score']}/100, Risk Level: {risk_res['risk_level']}")

    # 5. Points = 25
    assert risk_res["score"] == 25, f"Expected score 25, got {risk_res['score']}"
    print("5. Points Assigned: 25")

    # 6. Structured Findings Output
    findings = res["findings"]
    assert len(findings) > 0
    f_future = next(f for f in findings if f["type"] == "Future Timestamp")
    assert f_future["severity"] == "HIGH"
    assert f_future["points"] == 25
    print("6. Structured Finding Object:")
    print("  - Type    :", f_future["type"])
    print("  - Severity:", f_future["severity"])
    print("  - Points  :", f_future["points"])
    print("  - Reason  :", f_future["reason"])

    print("\n==================================================")
    print("ALL FUTURE TIMESTAMP PIPELINE TESTS PASSED!")
    print("==================================================")


if __name__ == "__main__":
    test_future_timestamp_pipeline()
