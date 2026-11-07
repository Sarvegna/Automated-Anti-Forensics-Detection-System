import sys
import os
import time
import logging
from datetime import datetime, timedelta, timezone

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.analysis_router import run_automated_analysis
from core.timestamp_analysis import analyze_timestamps
from core import storage


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


def test_real_evidence_timestamps(tmp_path):
    print("==================================================")
    print("TESTING REAL EVIDENCE FILE TIMESTAMP EXTRACTION")
    print("==================================================")

    real_file_path = str(tmp_path / "real_user_evidence.txt")

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


def test_corrupt_storage_json_is_backed_up_and_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(storage, "_ensure_data_dir", lambda: None)
    file_path = tmp_path / "history.json"
    file_path.write_text("{not valid json", encoding="utf-8")
    caplog.set_level(logging.WARNING, logger=storage.__name__)

    assert storage._load_json(str(file_path)) == []

    backups = list(tmp_path.glob("history.json.corrupt-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "{not valid json"
    assert file_path.name in caplog.text
    assert backups[0].name in caplog.text


def test_missing_storage_json_has_no_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_ensure_data_dir", lambda: None)
    file_path = tmp_path / "missing.json"

    assert storage._load_json(str(file_path)) == []
    assert list(tmp_path.glob("missing.json.corrupt-*")) == []


def test_valid_storage_json_loads_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_ensure_data_dir", lambda: None)
    file_path = tmp_path / "valid.json"
    content = '[{"case_id":"CASE-1","score":17}]'
    file_path.write_text(content, encoding="utf-8")

    assert storage._load_json(str(file_path)) == [{"case_id": "CASE-1", "score": 17}]
    assert list(tmp_path.glob("valid.json.corrupt-*")) == []


def test_audit_entry_timestamp_is_current_ist(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_ensure_data_dir", lambda: None)
    monkeypatch.setattr(storage, "AUDIT_FILE", str(tmp_path / "audit.json"))

    entry = storage.add_audit_log_entry("test", "CASE-1", "EVID-1", "Investigator")
    assert entry["timestamp"].endswith(" IST")
    parsed_timestamp = datetime.strptime(
        entry["timestamp"], "%Y-%m-%d %H:%M:%S IST"
    ).replace(tzinfo=timezone(timedelta(hours=5, minutes=30)))

    assert abs((parsed_timestamp - datetime.now(timezone(timedelta(hours=5, minutes=30)))).total_seconds()) <= 3


def test_audit_entry_timestamp_uses_fixed_ist_offset(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    monkeypatch.setattr(storage, "_ensure_data_dir", lambda: None)
    monkeypatch.setattr(storage, "AUDIT_FILE", str(tmp_path / "audit.json"))

    entry = storage.add_audit_log_entry("test", "CASE-1", "EVID-1", "Investigator")
    parsed_timestamp = datetime.strptime(
        entry["timestamp"], "%Y-%m-%d %H:%M:%S IST"
    ).replace(tzinfo=timezone(timedelta(hours=5, minutes=30)))
    expected_timestamp = datetime.now(timezone.utc)

    assert entry["timestamp"].endswith(" IST")
    assert parsed_timestamp.utcoffset() == timedelta(hours=5, minutes=30)
    assert abs((parsed_timestamp - expected_timestamp).total_seconds()) <= 3


if __name__ == "__main__":
    test_real_evidence_timestamps()
