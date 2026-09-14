import sys
import os
import sqlite3
from datetime import datetime, timedelta

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.browser_db_analysis import analyze_browser_database


def create_synthetic_chromium_db(db_path):
    """
    Creates a synthetic SQLite database matching Chromium browser history schema.
    """
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create Chromium schema tables
    cursor.execute("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 1
        );
    """)

    cursor.execute("""
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            FOREIGN KEY(url) REFERENCES urls(id)
        );
    """)

    # Populate synthetic visits
    # Base timestamp: Aug 2, 2026 14:00:00 UTC converted to WebKit timestamp
    # WebKit epoch is 1601-01-01 00:00:00 UTC
    webkit_base = int((datetime(2026, 8, 2, 14, 0, 0) - datetime(1601, 1, 1)).total_seconds() * 1000000)

    urls = [
        ("https://google.com", "Google Search", 1),
        ("https://github.com", "GitHub Repository", 1),
        ("https://target-site.org", "Target Portal", 1),
    ]

    for url, title, count in urls:
        cursor.execute("INSERT INTO urls (url, title, visit_count) VALUES (?, ?, ?)", (url, title, count))

    # Insert visits: visit 1 at 14:00, visit 2 at 14:05, visit 3 at 14:55 (50 min gap!)
    visit_offsets = [0, 5 * 60 * 1000000, 55 * 60 * 1000000]
    for url_id, offset in enumerate(visit_offsets, start=1):
        cursor.execute("INSERT INTO visits (url, visit_time) VALUES (?, ?)", (url_id, webkit_base + offset))

    conn.commit()
    conn.close()


def create_generic_non_browser_db(db_path):
    """
    Creates a generic SQLite database without browser history tables.
    """
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE app_config (key TEXT, value TEXT);")
    cursor.execute("INSERT INTO app_config VALUES ('theme', 'dark');")
    conn.commit()
    conn.close()


def run_tests():
    evidence_dir = os.path.join(project_root, "evidence", "input")
    os.makedirs(evidence_dir, exist_ok=True)

    browser_db_path = os.path.join(evidence_dir, "synthetic_browser_history.db")
    generic_db_path = os.path.join(evidence_dir, "generic_app.db")
    text_file_path = os.path.join(evidence_dir, "sample_evidence.txt")

    create_synthetic_chromium_db(browser_db_path)
    create_generic_non_browser_db(generic_db_path)

    print("--- TEST 1: Synthetic Chromium Browser History Database ---")
    res1 = analyze_browser_database(browser_db_path)
    print("Status:", res1["status"])
    print("Evidence Type:", res1["evidence_type"])
    print("Visits Extracted:", res1["data"].get("total_visits_extracted"))
    print("Gaps Detected:", res1["data"].get("total_gaps_detected"))
    print("Findings Generated:", len(res1["findings"]))
    if res1["findings"]:
        for f in res1["findings"]:
            print(f"  - [{f['finding_id']}] {f['type']} ({f['severity']}): {f['reason']}")
    print()

    print("--- TEST 2: Generic Non-Browser SQLite Database ---")
    res2 = analyze_browser_database(generic_db_path)
    print("Status:", res2["status"])
    print("Evidence Type:", res2["evidence_type"])
    print("Warnings:", res2["warnings"])
    print()

    print("--- TEST 3: Non-SQLite Text File ---")
    res3 = analyze_browser_database(text_file_path)
    print("Status:", res3["status"])
    print("Evidence Type:", res3["evidence_type"])
    print("Warnings:", res3["warnings"])
    print()

    assert res1["status"] == "SUCCESS", f"Test 1 failed: {res1}"
    assert len(res1["findings"]) == 1, f"Expected 1 timeline gap finding, got {len(res1['findings'])}"
    assert res2["status"] == "NOT_APPLICABLE", f"Test 2 failed: {res2}"
    assert res3["status"] == "NOT_APPLICABLE", f"Test 3 failed: {res3}"

    print("ALL BROWSER ARTIFACT ANALYSIS TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()
