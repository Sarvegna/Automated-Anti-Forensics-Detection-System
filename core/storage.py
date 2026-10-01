import os
import json
from datetime import datetime

# Resolve base project directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

HISTORY_FILE = os.path.join(DATA_DIR, "investigation_history.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.json")


def _ensure_data_dir():
    """Ensure data directory exists."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)


def _load_json(file_path):
    """Safely load JSON array from file."""
    _ensure_data_dir()
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_json(file_path, data):
    """Safely write JSON array to file."""
    _ensure_data_dir()
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# -----------------------------------------------------------------------------
# INVESTIGATION HISTORY API
# -----------------------------------------------------------------------------
def save_investigation_history(
    case_id,
    evidence_id,
    investigator,
    filename,
    artifact_type,
    risk_score,
    risk_level,
    status,
    pipeline_result,
    evidence_meta
):
    """
    Saves or updates a complete investigation record in persistent history.
    """
    history = _load_json(HISTORY_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "timestamp": timestamp,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "investigator": investigator,
        "filename": filename,
        "artifact_type": artifact_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status": status,
        "pipeline_result": pipeline_result,
        "evidence_meta": evidence_meta
    }

    updated = False
    for idx, item in enumerate(history):
        if item.get("case_id") == case_id and item.get("evidence_id") == evidence_id:
            history[idx] = record
            updated = True
            break

    if not updated:
        history.insert(0, record)  # Insert newest at beginning

    _save_json(HISTORY_FILE, history)
    return record


def get_investigation_history():
    """
    Returns list of all saved investigation records.
    """
    return _load_json(HISTORY_FILE)


def get_investigation_by_id(case_id, evidence_id):
    """
    Returns a specific investigation record by case_id and evidence_id.
    """
    history = _load_json(HISTORY_FILE)
    for record in history:
        if record.get("case_id") == case_id and record.get("evidence_id") == evidence_id:
            return record
    return None


# -----------------------------------------------------------------------------
# AUDIT LOG API
# -----------------------------------------------------------------------------
def add_audit_log_entry(action, case_id, evidence_id, investigator, details=""):
    """
    Appends an audit log entry with timestamp and details.
    """
    logs = _load_json(AUDIT_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    entry = {
        "timestamp": timestamp,
        "action": action,
        "case_id": case_id or "N/A",
        "evidence_id": evidence_id or "N/A",
        "investigator": investigator or "N/A",
        "details": details
    }

    logs.insert(0, entry)  # Newest first
    _save_json(AUDIT_FILE, logs)
    return entry


def get_audit_logs():
    """
    Returns all audit log entries.
    """
    return _load_json(AUDIT_FILE)
