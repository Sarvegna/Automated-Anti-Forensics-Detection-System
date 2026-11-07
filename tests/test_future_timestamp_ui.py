import sys
import os
import ctypes
import shutil
from datetime import datetime, timezone
import pytest

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.analysis_router import run_automated_analysis
from core.evidence_object import create_evidence_object
from core.timestamp_analysis import analyze_timestamps


def _set_windows_file_times(file_path):
    if os.name != "nt":
        return False

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.SetFileTime.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.SetFileTime.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    def to_filetime(value):
        filetime_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        ticks = int((value - filetime_epoch).total_seconds()) * 10_000_000
        return wintypes.FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)

    created = to_filetime(datetime(2035, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
    modified = to_filetime(datetime(2035, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
    accessed = to_filetime(datetime(2035, 1, 2, 12, 0, 0, tzinfo=timezone.utc))
    handle = kernel32.CreateFileW(file_path, 0x0100, 0x00000007, None, 3, 0x00000080, None)
    if handle == wintypes.HANDLE(-1).value:
        return False

    try:
        return bool(kernel32.SetFileTime(
            handle, ctypes.byref(created), ctypes.byref(accessed), ctypes.byref(modified)
        ))
    finally:
        kernel32.CloseHandle(handle)


def test_future_timestamp_pipeline(tmp_path, monkeypatch):
    print("==================================================")
    print("TESTING FUTURE TIMESTAMP LOCAL PATH PIPELINE")
    print("==================================================")

    sample_file = os.path.join(project_root, "evidence", "input", "future_timestamp.txt")
    test_file = str(tmp_path / "future_timestamp.txt")
    shutil.copyfile(sample_file, test_file)
    source_metadata = {
        "input_method": "local_path",
        "is_web_upload": False,
        "filename": "future_timestamp.txt"
    }

    evidence_obj = create_evidence_object(test_file, source_metadata=source_metadata)

    def analyze_with_controlled_times(evidence_input, source_metadata=None):
        if not _set_windows_file_times(test_file):
            pytest.skip("Cannot set the evidence copy's creation time on this platform.")
        return analyze_timestamps(evidence_input, source_metadata=source_metadata)

    monkeypatch.setattr("core.analysis_router.analyze_timestamps", analyze_with_controlled_times)

    res = run_automated_analysis(evidence_obj, source_metadata=source_metadata)

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
    assert risk_res["risk_level"] == "LOW", f"Expected risk_level LOW for score {risk_res['score']}, got {risk_res['risk_level']}"
    print(f"4. Aggregated Risk Score: {risk_res['score']}/100, Risk Level: {risk_res['risk_level']}")

    # 5. Points = 25
    assert risk_res["score"] == 25, f"Expected score 25, got {risk_res['score']}"
    print("5. Points Assigned: 25")

    # 6. Structured Findings Output
    findings = res["findings"]
    assert len(findings) > 0
    f_future = next(f for f in findings if f["type"] == "Future Timestamp (Timestamp)")
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
