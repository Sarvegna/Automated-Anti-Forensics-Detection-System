# test_group2_logging_wording.py
# Regression tests for Group-2: debug logging migration and wording fixes.
#
# Logging tests:
#   - core/timestamp_analysis.py uses logger.debug(), not print()
#   - core/analysis_router.py uses logger.debug(), not print()
#   - Both loggers are named after their module (__name__)
#
# Wording tests (source-level assertions on app/streamlit_app.py):
#   - MAIN ANALYSIS OVERVIEW removed
#   - Module Count corrected
#   - hidden and system-hidden corrected
#   - timestomping tools corrected
#   - Chromium-based browser corrected

import sys, os
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import logging
import unittest
import io


# ---------------------------------------------------------------------------
# Logging migration: timestamp_analysis
# ---------------------------------------------------------------------------

def test_timestamp_analysis_no_print_statements():
    """core/timestamp_analysis.py must contain no bare print() calls."""
    path = os.path.join(project_root, "core", "timestamp_analysis.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    lines_with_print = [
        (i + 1, l.strip())
        for i, l in enumerate(src.splitlines())
        if l.strip().startswith("print(") and "[DEBUG]" in l
    ]
    assert not lines_with_print, (
        f"[DEBUG] print() calls still present in timestamp_analysis.py: {lines_with_print}"
    )


def test_timestamp_analysis_uses_logger():
    """core/timestamp_analysis.py must declare a module-level logger."""
    path = os.path.join(project_root, "core", "timestamp_analysis.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    assert "import logging" in src, "logging not imported in timestamp_analysis.py"
    assert "getLogger(__name__)" in src, "Module-level logger not declared in timestamp_analysis.py"
    assert "logger.debug(" in src, "logger.debug() calls not found in timestamp_analysis.py"


def test_timestamp_analysis_logger_emits_at_debug(tmp_path):
    """analyze_timestamps() must emit log records at DEBUG level, not at WARNING or above."""
    from core.timestamp_analysis import analyze_timestamps

    # Create a real minimal temp file so the function can read timestamps
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 4)

    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.DEBUG)

    ts_logger = logging.getLogger("core.timestamp_analysis")
    ts_logger.setLevel(logging.DEBUG)
    ts_logger.addHandler(handler)
    try:
        analyze_timestamps(str(dummy))
        output = log_capture.getvalue()
        assert "TIMESTAMP NUMERICAL COMPARISON CHECK" in output, (
            "Expected debug banner not emitted by logger"
        )
    finally:
        ts_logger.removeHandler(handler)


def test_timestamp_analysis_no_stdout_pollution(capsys, tmp_path):
    """analyze_timestamps() must not write anything to stdout."""
    from core.timestamp_analysis import analyze_timestamps
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 4)
    analyze_timestamps(str(dummy))
    captured = capsys.readouterr()
    assert captured.out == "", (
        f"analyze_timestamps() wrote to stdout: {captured.out!r}"
    )


# ---------------------------------------------------------------------------
# Logging migration: analysis_router
# ---------------------------------------------------------------------------

def test_analysis_router_no_print_statements():
    """core/analysis_router.py must contain no bare [DEBUG] print() calls."""
    path = os.path.join(project_root, "core", "analysis_router.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    lines_with_print = [
        (i + 1, l.strip())
        for i, l in enumerate(src.splitlines())
        if l.strip().startswith("print(") and "[DEBUG]" in l
    ]
    assert not lines_with_print, (
        f"[DEBUG] print() calls still present in analysis_router.py: {lines_with_print}"
    )


def test_analysis_router_uses_logger():
    """core/analysis_router.py must declare a module-level logger."""
    path = os.path.join(project_root, "core", "analysis_router.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    assert "import logging" in src, "logging not imported in analysis_router.py"
    assert "getLogger(__name__)" in src, "Module-level logger not declared in analysis_router.py"
    assert "logger.debug(" in src, "logger.debug() calls not found in analysis_router.py"


# ---------------------------------------------------------------------------
# Wording fixes: streamlit_app.py source assertions
# ---------------------------------------------------------------------------

def _app_source():
    path = os.path.join(project_root, "app", "streamlit_app.py")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_no_main_analysis_overview_heading():
    src = _app_source()
    assert "MAIN ANALYSIS OVERVIEW" not in src, (
        "Redundant 'MAIN' still present in Analysis Overview page heading"
    )
    assert "ANALYSIS OVERVIEW" in src, (
        "Expected heading 'ANALYSIS OVERVIEW' not found after fix"
    )


def test_module_count_chart_axis_title():
    src = _app_source()
    assert "'Module Count'" in src or '"Module Count"' in src, (
        "Chart axis title not corrected to 'Module Count'"
    )
    assert "'Modules Count'" not in src and '"Modules Count"' not in src, (
        "Old chart axis title 'Modules Count' still present"
    )


def test_hidden_file_wording_corrected():
    src = _app_source()
    assert "hidden and system-hidden" in src, (
        "Hidden File scope description not corrected to 'hidden and system-hidden'"
    )
    assert "hidden or hidden-system" not in src, (
        "Old wording 'hidden or hidden-system' still present"
    )


def test_yara_wording_corrected():
    src = _app_source()
    assert "timestomping tools" in src, (
        "YARA scope description not corrected to 'timestomping tools'"
    )
    assert "timestompers" not in src, (
        "Old wording 'timestompers' still present"
    )


def test_browser_wording_corrected():
    src = _app_source()
    assert "Chromium-based browser" in src, (
        "Browser scope description not corrected to 'Chromium-based browser'"
    )
    assert "Chromium/Firefox" not in src, (
        "Old wording 'Chromium/Firefox' still present"
    )
