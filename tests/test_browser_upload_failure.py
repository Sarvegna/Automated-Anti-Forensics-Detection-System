import pytest

from core import storage
from core.browser_upload import run_browser_upload_analysis


def test_browser_upload_analysis_failure_is_audited(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.json"
    monkeypatch.setattr(storage, "AUDIT_FILE", str(audit_path))
    monkeypatch.setattr(storage, "_ensure_data_dir", lambda: None)

    def fail_analysis(*args, **kwargs):
        raise ValueError("synthetic analysis failure")

    with pytest.raises(ValueError, match="synthetic analysis failure"):
        run_browser_upload_analysis(
            fail_analysis,
            "CASE-1",
            "EVID-1",
            "Investigator",
            "synthetic-upload.bin",
        )

    entries = storage.get_audit_logs()
    assert len(entries) == 1
    assert entries[0]["action"] == "Analysis Failed"
    assert entries[0]["details"] == "ValueError: synthetic analysis failure"
