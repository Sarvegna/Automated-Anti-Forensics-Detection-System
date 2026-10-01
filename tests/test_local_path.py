import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.analysis_router import run_automated_analysis
from core.validation import validate_evidence_file


def test_local_path_processing():
    print("==================================================")
    print("TESTING LOCAL EVIDENCE PATH PROCESSING & PIPELINE")
    print("==================================================")

    # 1. Invalid path test
    invalid_path = "non_existent_file_xyz_123.txt"
    is_valid, msg = validate_evidence_file(invalid_path)
    assert not is_valid, "Expected invalid path validation to fail"
    print("Invalid path check passed:", msg)

    # 2. Local path test on anomaly_test.txt
    local_path = os.path.join(project_root, "evidence", "input", "anomaly_test.txt")
    source_metadata = {
        "input_method": "local_path",
        "is_web_upload": False,
        "filename": "anomaly_test.txt"
    }

    res = run_automated_analysis(local_path, source_metadata=source_metadata)

    assert res["status"] == "SUCCESS", f"Expected SUCCESS status, got {res['status']}"
    assert res["source_type"] == "individual_file"
    assert res["evidence_context"]["input_method"] == "local_path"
    assert res["evidence_context"]["timestamp_provenance"] == "local_filesystem"
    assert res["evidence_context"]["sha256"] is not None
    assert res["sha256"] == res["evidence_context"]["sha256"]

    # 3. Verify Modified Before Created anomaly is detected
    ts_res = res["timestamp_result"]
    assert ts_res["anomaly_detected"], "Expected timestamp anomaly to be detected on local file path"
    ind_types = [ind["type"] for ind in ts_res["indicators"]]
    assert "Modified Before Created" in ind_types, f"Expected 'Modified Before Created' in indicators, got {ind_types}"

    print("\nLocal Path Analysis Results:")
    print(f"  - Status               : {res['status']}")
    print(f"  - Source Type          : {res['source_type']}")
    print(f"  - Input Method         : {res['evidence_context']['input_method']}")
    print(f"  - Timestamp Provenance : {res['evidence_context']['timestamp_provenance']}")
    print(f"  - SHA-256              : {res['sha256']}")
    print(f"  - Anomaly Detected     : {ts_res['anomaly_detected']}")
    print(f"  - Indicators           : {ind_types}")

    print("\n==================================================")
    print("ALL LOCAL PATH PROCESSING TESTS PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    test_local_path_processing()
