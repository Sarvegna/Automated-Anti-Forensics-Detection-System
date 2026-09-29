"""
Tests for the uploaded-file last_modified timestamp handling
extracted from app/streamlit_app.py (browser upload path).

The logic under test (lines 398-402 of streamlit_app.py):

    if hasattr(uploaded_file, "last_modified") and uploaded_file.last_modified:
        try:
            source_metadata["last_modified"] = datetime.fromtimestamp(
                uploaded_file.last_modified / 1000.0, tz=timezone.utc
            )
        except Exception:
            pass

Before the fix, `timezone` was not imported (only `datetime` was), which
caused a silent NameError so `last_modified` was never stored.
"""

import sys
import os
from datetime import datetime, timezone, timedelta

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)


def convert_last_modified(last_modified_ms):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(last_modified_ms / 1000.0, tz=timezone.utc)


def simulate_upload_handler(uploaded_file_stub):
    from datetime import datetime, timezone
    source_metadata = {
        "input_method": "browser_upload",
        "is_web_upload": True,
        "filename": getattr(uploaded_file_stub, "name", "test.bin"),
        "size": getattr(uploaded_file_stub, "size", 0),
    }
    if hasattr(uploaded_file_stub, "last_modified") and uploaded_file_stub.last_modified:
        try:
            source_metadata["last_modified"] = datetime.fromtimestamp(
                uploaded_file_stub.last_modified / 1000.0, tz=timezone.utc
            )
        except Exception:
            pass
    return source_metadata


class _FakeUploadedFile:
    def __init__(self, name="evidence.bin", size=1024, last_modified=None):
        self.name = name
        self.size = size
        self.last_modified = last_modified


def test_last_modified_is_utc_aware():
    stub = _FakeUploadedFile(last_modified=1_000_000_000_000)
    meta = simulate_upload_handler(stub)
    assert "last_modified" in meta, "last_modified must be stored in source_metadata"
    dt = meta["last_modified"]
    assert isinstance(dt, datetime)
    assert dt.tzinfo is not None
    assert dt.utcoffset() == timedelta(0)


def test_last_modified_correct_value():
    # Derive the expected UTC datetime from the same epoch value so the
    # assertion is immune to local-TZ confusion.
    ms = 1_705_316_400_000
    expected = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    stub = _FakeUploadedFile(last_modified=ms)
    meta = simulate_upload_handler(stub)
    dt = meta["last_modified"]
    assert dt == expected, f"Expected {expected!r}, got {dt!r}"
    assert dt.year == 2024
    assert dt.month == 1
    assert dt.day == 15
    assert dt.minute == 0
    assert dt.second == 0


def test_last_modified_absent_when_none():
    stub = _FakeUploadedFile(last_modified=None)
    meta = simulate_upload_handler(stub)
    assert "last_modified" not in meta


def test_last_modified_absent_when_zero():
    stub = _FakeUploadedFile(last_modified=0)
    meta = simulate_upload_handler(stub)
    assert "last_modified" not in meta


def test_last_modified_no_attribute():
    class _NoAttrFile:
        name = "test.bin"
        size = 512
    meta = simulate_upload_handler(_NoAttrFile())
    assert "last_modified" not in meta


def test_convert_last_modified_epoch_zero():
    dt = convert_last_modified(0)
    assert dt == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_convert_last_modified_subsecond():
    dt = convert_last_modified(1_500)
    assert dt.second == 1
    assert dt.microsecond == 500_000


def test_timezone_importable():
    try:
        from datetime import timezone as _tz
    except ImportError as exc:
        raise AssertionError("datetime.timezone could not be imported") from exc


def test_streamlit_app_imports_timezone():
    app_path = os.path.join(project_root, "app", "streamlit_app.py")
    assert os.path.isfile(app_path)
    with open(app_path, encoding="utf-8") as fh:
        source = fh.read()
    assert "from datetime import datetime, timezone" in source, (
        "streamlit_app.py must import timezone alongside datetime."
    )


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
