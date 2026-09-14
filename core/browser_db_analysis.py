import os
import sqlite3
from datetime import datetime, timedelta
from core.browser_analysis import analyze_browser_history
from core.findings import create_finding

SQLITE_HEADER = b"SQLite format 3\x00"
CHROMIUM_EPOCH = datetime(1601, 1, 1)


def convert_webkit_timestamp(webkit_time):
    """
    Converts a Chromium WebKit timestamp (microseconds since Jan 1, 1601 UTC)
    to a Python datetime object.
    """
    if not webkit_time or webkit_time == 0:
        return None
    try:
        return CHROMIUM_EPOCH + timedelta(microseconds=webkit_time)
    except Exception:
        return None


def is_sqlite_file(file_path):
    """
    Validates whether a file has the standard SQLite 3 header magic bytes.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            return header == SQLITE_HEADER
    except Exception:
        return False


def analyze_browser_database(file_path, evidence_reference=None):
    """
    Analyzes a SQLite browser database (Chromium/Chrome/Edge).

    Returns a standardized ModuleResult dictionary:
    {
        "module_name": "Browser Artifact Analysis",
        "status": "SUCCESS" | "NOT_APPLICABLE" | "FAILED" | "CORRUPTED",
        "evidence_type": "Browser Database" | "Non-Browser SQLite" | "Non-SQLite File",
        "findings": [...],
        "data": {...},
        "warnings": [...],
        "errors": [...],
        "metadata": {...}
    }
    """
    if evidence_reference is None:
        evidence_reference = os.path.basename(file_path)

    # 1. Validate SQLite header structure
    if not is_sqlite_file(file_path):
        return {
            "module_name": "Browser Artifact Analysis",
            "status": "NOT_APPLICABLE",
            "evidence_type": "Non-SQLite File",
            "findings": [],
            "data": {},
            "warnings": ["File does not contain valid SQLite magic bytes."],
            "errors": [],
            "metadata": {"file_path": file_path}
        }

    conn = None
    try:
        # 2. Open SQLite database safely in read-only mode
        abs_path = os.path.abspath(file_path).replace("\\", "/")
        uri = f"file:{abs_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        cursor = conn.cursor()

        # 3. Detect available tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        # Check for Chromium history schema tables ('urls' and 'visits')
        if "urls" not in tables or "visits" not in tables:
            return {
                "module_name": "Browser Artifact Analysis",
                "status": "NOT_APPLICABLE",
                "evidence_type": "SQLite Database (Non-Browser)",
                "findings": [],
                "data": {"tables": tables},
                "warnings": [f"SQLite database contains tables {tables}, but lacks Chromium 'urls'/'visits' schema."],
                "errors": [],
                "metadata": {"file_path": file_path, "tables": tables}
            }

        # 4. Extract URLs, titles, visit counts, and visit timestamps
        query = """
            SELECT urls.url, urls.title, urls.visit_count, visits.visit_time
            FROM visits
            JOIN urls ON visits.url = urls.id
            ORDER BY visits.visit_time ASC
        """
        cursor.execute(query)
        rows = cursor.fetchall()

        normalized_visits = []
        for url, title, visit_count, webkit_time in rows:
            dt = convert_webkit_timestamp(webkit_time)
            if dt:
                normalized_visits.append({
                    "url": url or "",
                    "title": title or "",
                    "visit_count": visit_count or 1,
                    "visit_time": dt
                })

        # 5. Detect timeline gaps using browser analysis module
        history_analysis = analyze_browser_history(normalized_visits)
        gap_indicators = history_analysis.get("indicators", [])

        # 6. Build structured findings for findings engine
        findings = []
        for gap in gap_indicators:
            finding = create_finding(
                finding_type="Timeline Gap (Browser)",
                severity="MEDIUM",
                evidence_reference=evidence_reference,
                reason=gap["explanation"],
                source="Browser History"
            )
            findings.append(finding)

        return {
            "module_name": "Browser Artifact Analysis",
            "status": "SUCCESS",
            "evidence_type": "Browser Database (Chromium)",
            "findings": findings,
            "data": {
                "total_visits_extracted": len(normalized_visits),
                "total_gaps_detected": len(gap_indicators),
                "visits": normalized_visits,
                "gap_indicators": gap_indicators
            },
            "warnings": [],
            "errors": [],
            "metadata": {
                "file_path": file_path,
                "tables": tables,
                "schema_type": "Chromium"
            }
        }

    except sqlite3.DatabaseError as e:
        return {
            "module_name": "Browser Artifact Analysis",
            "status": "CORRUPTED",
            "evidence_type": "Corrupted SQLite Database",
            "findings": [],
            "data": {},
            "warnings": [],
            "errors": [f"SQLite DatabaseError: {str(e)}"],
            "metadata": {"file_path": file_path}
        }
    except Exception as e:
        return {
            "module_name": "Browser Artifact Analysis",
            "status": "FAILED",
            "evidence_type": "Browser Database Error",
            "findings": [],
            "data": {},
            "warnings": [],
            "errors": [f"Unexpected error during browser analysis: {str(e)}"],
            "metadata": {"file_path": file_path}
        }
    finally:
        if conn:
            conn.close()
