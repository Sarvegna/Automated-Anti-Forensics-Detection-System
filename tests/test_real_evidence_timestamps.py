import sys
import os
import time
from datetime import datetime, timezone

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.analysis_router import run_automated_analysis
from core.timestamp_analysis import analyze_timestamps


def set_win_file_timestamps(filepath, created_dt, modified_dt, accessed_dt):
    """
    Sets exact CreationTime, LastWriteTime, and LastAccessTime on a Windows file.
    """
    created_ts = created_dt.timestamp()
    modified_ts = modified_dt.timestamp()
    accessed_ts = accessed_dt.timestamp()

    try:
        import ctypes
        from ctypes import wintypes

        FILE_WRITE_ATTRIBUTES = 0x0100
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

        def to_filetime(ts):
            ns100 = int((ts + 11644473600) * 10000000)
            return wintypes.FILETIME(ns100 & 0xFFFFFFFF, ns100 >> 32)

        c_file = to_filetime(created_ts)
        m_file = to_filetime(modified_ts)
        a_file = to_filetime(accessed_ts)

        handle = ctypes.windll.kernel32.CreateFileW(
            filepath, FILE_WRITE_ATTRIBUTES, 7, None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None
        )
        if handle != -1:
            ctypes.windll.kernel32.SetFileTime(handle, ctypes.byref(c_file), ctypes.byref(a_file), ctypes.byref(m_file))
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
    except Exception as e:
        print("Failed to set Win32 timestamps:", e)

    # Fallback to os.utime for modified/accessed
    os.utime(filepath, (accessed_ts, modified_ts))
    return False


def test_real_evidence_timestamps():
    print("==================================================")
    print("TESTING REAL EVIDENCE FILE TIMESTAMP EXTRACTION")
    print("==================================================")

    evidence_dir = os.path.join(project_root, "evidence", "input")
    os.makedirs(evidence_dir, exist_ok=True)
    real_file_path = os.path.join(evidence_dir, "real_user_evidence.txt")

    # Create real evidence file on disk
    with open(real_file_path, "w") as f:
        f.write("Real user evidence file content.\n")

    # Target timestamps requested by user:
    # Created: 25 October 2025 (10:00:00 UTC)
    # Modified: 15 August 2026 (14:30:00 UTC)
    target_created = datetime(2025, 10, 25, 10, 0, 0, tzinfo=timezone.utc)
    target_modified = datetime(2026, 8, 15, 14, 30, 0, tzinfo=timezone.utc)
    target_accessed = datetime(2026, 8, 26, 8, 0, 0, tzinfo=timezone.utc)

    set_win_file_timestamps(real_file_path, target_created, target_modified, target_accessed)

    print("\n--- Running Timestamp Analysis on Original File Path ---")
    ts_res = analyze_timestamps(real_file_path)

    print("\nExtracted Timestamps:")
    print("  Created :", ts_res["created"].strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("  Modified:", ts_res["modified"].strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("  Accessed:", ts_res["accessed"].strftime("%Y-%m-%d %H:%M:%S UTC"))

    print("\n--- Running Full Automated Analysis Pipeline ---")
    pipeline_res = run_automated_analysis(real_file_path)

    ts_res_pipe = pipeline_res["timestamp_result"]
    print("\nPipeline Result Timestamps:")
    print("  Created :", ts_res_pipe["created"].strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("  Modified:", ts_res_pipe["modified"].strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("  Accessed:", ts_res_pipe["accessed"].strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("  Anomaly Detected:", ts_res_pipe["anomaly_detected"])
    print("  Indicators:", ts_res_pipe["indicators"])

    assert ts_res_pipe["created"].year == 2025
    assert ts_res_pipe["created"].month == 10
    assert ts_res_pipe["created"].day == 25
    assert ts_res_pipe["modified"].year == 2026
    assert ts_res_pipe["modified"].month == 8
    assert ts_res_pipe["modified"].day == 15
    assert not ts_res_pipe["anomaly_detected"]

    print("\n==================================================")
    print("REAL EVIDENCE FILE TIMESTAMP EXTRACTION PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    test_real_evidence_timestamps()
