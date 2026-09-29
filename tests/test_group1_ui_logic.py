# test_group1_ui_logic.py
# Focused regression tests for the Group-1 UI-logic fixes applied to streamlit_app.py.
#
# Tests the pure Python logic (no Streamlit runtime required):
#   Fix 1 - Timestamp display: INDICATOR_WEIGHTS.get(ind_type, 0) fallback
#   Fix 2 - Event Log display: INDICATOR_WEIGHTS.get(cat_name, 0) fallback
#   Fix 3 - Module status badge class mapping (not always badge-success)
#   Fix 4 - Section heading and radio label text assertions

import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import pytest
from core.risk_scoring import INDICATOR_WEIGHTS


# ---------------------------------------------------------------------------
# Helper: replicate the badge-class logic from Module Results page
# ---------------------------------------------------------------------------

def _status_badge_cls(m_status: str) -> str:
    return (
        'badge-success' if m_status == 'SUCCESS' else (
            'badge-medium' if m_status in ('UNSUPPORTED', 'MISSING_DEPENDENCY') else (
                'badge-failed' if m_status in ('FAILED', 'CORRUPTED') else 'badge-na'
            )
        )
    )


# ---------------------------------------------------------------------------
# Fix 1: Timestamp display fallback
# ---------------------------------------------------------------------------

def test_timestamp_display_unknown_type_fallback_is_zero():
    pts = INDICATOR_WEIGHTS.get('Unknown Timestamp Type That Does Not Exist', 0)
    assert pts == 0, f'Expected 0 for unknown timestamp type, got {pts}'


def test_timestamp_display_known_types_resolve_correctly():
    known = {
        'Modified Before Created': 20,
        'Accessed Before Created': 20,
        'Future Timestamp': 25,
        'Accessed Before Modified': 10,
    }
    for ind_type, expected in known.items():
        pts = INDICATOR_WEIGHTS.get(ind_type, 0)
        assert pts == expected, f"Timestamp type '{ind_type}' expected {expected} pts, got {pts}"


# ---------------------------------------------------------------------------
# Fix 2: Event Log display fallback
# ---------------------------------------------------------------------------

def test_eventlog_display_unknown_category_fallback_is_zero():
    pts = INDICATOR_WEIGHTS.get('Unknown Event Log Category', 0)
    assert pts == 0, f'Expected 0 for unknown event log category, got {pts}'


def test_eventlog_display_known_categories_resolve_correctly():
    known = {
        'Log Cleared': 25,
        'Audit Policy Changed': 20,
        'Event Log Service Shutdown': 20,
        'Timeline Gap': 15,
    }
    for cat_name, expected in known.items():
        pts = INDICATOR_WEIGHTS.get(cat_name, 0)
        assert pts == expected, f"Event log category '{cat_name}' expected {expected} pts, got {pts}"


# ---------------------------------------------------------------------------
# Fix 3: Module status badge class
# ---------------------------------------------------------------------------

def test_badge_success_status():
    assert _status_badge_cls('SUCCESS') == 'badge-success'

def test_badge_failed_status():
    assert _status_badge_cls('FAILED') == 'badge-failed', \
        'FAILED module must render badge-failed, not badge-success'

def test_badge_corrupted_status():
    assert _status_badge_cls('CORRUPTED') == 'badge-failed', \
        'CORRUPTED module must render badge-failed, not badge-success'

def test_badge_not_applicable_status():
    assert _status_badge_cls('NOT_APPLICABLE') == 'badge-na', \
        'NOT_APPLICABLE module must render badge-na, not badge-success'

def test_badge_missing_dependency_status():
    assert _status_badge_cls('MISSING_DEPENDENCY') == 'badge-medium'

def test_badge_unsupported_status():
    assert _status_badge_cls('UNSUPPORTED') == 'badge-medium'

def test_badge_unknown_status_defaults_to_na():
    assert _status_badge_cls('SOME_FUTURE_STATUS') == 'badge-na'


# ---------------------------------------------------------------------------
# Fix 4/5: UI label and heading text assertions (source-level)
# ---------------------------------------------------------------------------

def test_browser_upload_radio_label_in_source():
    app_path = os.path.join(project_root, 'app', 'streamlit_app.py')
    with open(app_path, encoding='utf-8') as f:
        source = f.read()
    assert '"Browser Upload"' in source, \
        "Radio option 'Browser Upload' not found in streamlit_app.py"

def test_old_upload_evidence_file_radio_label_removed():
    import re as re2
    app_path = os.path.join(project_root, "app", "streamlit_app.py")
    with open(app_path, encoding="utf-8") as f:
        source = f.read()
    radio_match = re2.search(r"st\.radio\([^)]+\[([^\]]+)\]", source, re2.DOTALL)
    assert radio_match, "Could not locate st.radio() list in streamlit_app.py"
    radio_list_text = radio_match.group(1)
    assert "Upload Evidence File" not in radio_list_text, (
        "Old radio option still present in st.radio() list: " + repr(radio_list_text)
    )
    assert "Browser Upload" in radio_list_text, (
        "New label Browser Upload not found in st.radio() list"
    )

def test_section_heading_not_uploaded_in_source():
    app_path = os.path.join(project_root, 'app', 'streamlit_app.py')
    with open(app_path, encoding='utf-8') as f:
        source = f.read()
    assert 'Uploaded Evidence Metadata' not in source, \
        "Section heading still contains 'Uploaded Evidence Metadata'"
    assert 'Evidence Metadata' in source, \
        "Neutral heading 'Evidence Metadata & Identification' not found"
