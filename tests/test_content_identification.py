import sys
import os
import sqlite3
import tempfile

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.evidence_identifier import identify_evidence
from core.analysis_router import run_automated_analysis


def create_synthetic_chromium_db(db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);")
    cursor.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);")
    cursor.execute("INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1);")
    cursor.execute("INSERT INTO visits VALUES (1, 1, 13300000000000000);")
    conn.commit()
    conn.close()


def create_generic_sqlite_db(db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE app_config (key TEXT, value TEXT);")
    cursor.execute("INSERT INTO app_config VALUES ('setting', 'enabled');")
    conn.commit()
    conn.close()


def run_identification_tests():
    print("==================================================")
    print("RUNNING CONTENT-BASED EVIDENCE IDENTIFICATION TESTS")
    print("==================================================")

    test_dir = tempfile.mkdtemp()

    try:
        # Test 1: Standard .db Chromium Browser Database
        t1_path = os.path.join(test_dir, "browser.db")
        create_synthetic_chromium_db(t1_path)
        res1 = identify_evidence(t1_path)
        print("\nTest 1 - Standard .db Chromium DB:")
        print("  Evidence Type:", res1["evidence_type"])
        print("  Confidence:", res1["confidence"])
        print("  Routed Module:", res1["routed_module"])
        assert res1["evidence_type"] == "Browser Database (Chromium)"
        assert res1["confidence"] == "HIGH"
        assert res1["routed_module"] == "Browser Artifact Analysis"

        # Test 2: Extensionless 'History' Chromium Database
        t2_path = os.path.join(test_dir, "History")
        create_synthetic_chromium_db(t2_path)
        res2 = identify_evidence(t2_path)
        print("\nTest 2 - Extensionless 'History' Chromium DB:")
        print("  Evidence Type:", res2["evidence_type"])
        print("  Confidence:", res2["confidence"])
        print("  Routed Module:", res2["routed_module"])
        assert res2["evidence_type"] == "Browser Database (Chromium)"
        assert res2["confidence"] == "HIGH"
        assert res2["routed_module"] == "Browser Artifact Analysis"

        # Test 3: Generic SQLite Database (random.db with app_config table)
        t3_path = os.path.join(test_dir, "random.db")
        create_generic_sqlite_db(t3_path)
        res3 = identify_evidence(t3_path)
        print("\nTest 3 - Generic Non-Browser SQLite DB:")
        print("  Evidence Type:", res3["evidence_type"])
        print("  Confidence:", res3["confidence"])
        print("  Routed Module:", res3["routed_module"])
        assert res3["evidence_type"] == "SQLite Database (Non-Browser)"
        assert res3["confidence"] == "HIGH"
        assert res3["routed_module"] == "General Analysis only"

        # Test 4: Non-SQLite Text File
        t4_path = os.path.join(test_dir, "sample.txt")
        with open(t4_path, "w") as f:
            f.write("This is a plain text evidence file.\n")
        res4 = identify_evidence(t4_path)
        print("\nTest 4 - Non-SQLite Text File:")
        print("  Evidence Type:", res4["evidence_type"])
        print("  Confidence:", res4["confidence"])
        print("  Routed Module:", res4["routed_module"])
        assert res4["evidence_type"] == "General File"
        assert res4["routed_module"] == "General Analysis only"

        # Test 5: Incorrect/Unusual Extension containing SQLite (history.evtx containing SQLite DB)
        t5_path = os.path.join(test_dir, "history.evtx")
        create_synthetic_chromium_db(t5_path)
        res5 = identify_evidence(t5_path)
        print("\nTest 5 - Mislabeled File (history.evtx containing SQLite Chromium DB):")
        print("  Evidence Type:", res5["evidence_type"])
        print("  Confidence:", res5["confidence"])
        print("  Detection Method:", res5["detection_method"])
        print("  Routed Module:", res5["routed_module"])
        assert res5["evidence_type"] == "Browser Database (Chromium)"
        assert res5["confidence"] == "HIGH"
        assert res5["routed_module"] == "Browser Artifact Analysis"

        # Test 6: Invalid/Corrupted File (0-byte file)
        t6_path = os.path.join(test_dir, "empty_corrupt.db")
        with open(t6_path, "wb") as f:
            pass
        res6 = identify_evidence(t6_path)
        print("\nTest 6 - Corrupted / Empty 0-byte File:")
        print("  Evidence Type:", res6["evidence_type"])
        print("  Confidence:", res6["confidence"])
        print("  Reason:", res6["reason"])
        assert res6["confidence"] == "LOW"
        assert res6["routed_module"] == "General Analysis only"

        # Test 7: E01 Signature Detection
        t7_path = os.path.join(test_dir, "evidence_image.E01")
        with open(t7_path, "wb") as f:
            f.write(b"EVF\x09\x0d\x0a\xff\x00HeaderDataChunkHere...")
        res7 = identify_evidence(t7_path)
        print("\nTest 7 - E01 Signature Detection:")
        print("  Evidence Type:", res7["evidence_type"])
        print("  Confidence:", res7["confidence"])
        print("  Routed Module:", res7["routed_module"])
        assert res7["evidence_type"] == "E01 Forensic Image"
        assert res7["confidence"] == "HIGH"
        assert res7["routed_module"] == "General Analysis only"

        # Test 8: EVTX Identification (with ElfFile header)
        t8_path = os.path.join(test_dir, "renamed_log.tmp")
        with open(t8_path, "wb") as f:
            f.write(b"ElfFile\x00EVTXHeaderChunkDummyData...")
        res8 = identify_evidence(t8_path)
        print("\nTest 8 - EVTX Magic Signature (Extensionless / renamed .tmp):")
        print("  Evidence Type:", res8["evidence_type"])
        print("  Confidence:", res8["confidence"])
        print("  Routed Module:", res8["routed_module"])
        assert res8["evidence_type"] == "Windows Event Log"
        assert res8["confidence"] == "HIGH"
        assert res8["routed_module"] == "Event Log Analysis"

        # Test 9: Ambiguity Disambiguation (.raw disk image vs .raw memory vs .img disk image)
        t9_raw_disk = os.path.join(test_dir, "disk.raw")
        with open(t9_raw_disk, "wb") as f:
            buf = bytearray(512)
            buf[510] = 0x55
            buf[511] = 0xAA
            f.write(buf)
        res9_disk = identify_evidence(t9_raw_disk)
        print("\nTest 9a - Ambiguity Disambiguation (.raw Disk Image with MBR):")
        print("  Evidence Type:", res9_disk["evidence_type"])
        print("  Routed Module:", res9_disk["routed_module"])
        assert res9_disk["evidence_type"] == "Disk Image"
        assert res9_disk["routed_module"] == "General Analysis only"

        t9_raw_mem = os.path.join(test_dir, "ram.raw")
        with open(t9_raw_mem, "wb") as f:
            f.write(b"PAGEDUMP" + b"\x00" * 1024)
        res9_mem = identify_evidence(t9_raw_mem)
        print("\nTest 9b - Ambiguity Disambiguation (.raw Memory Crashdump):")
        print("  Evidence Type:", res9_mem["evidence_type"])
        print("  Routed Module:", res9_mem["routed_module"])
        assert res9_mem["evidence_type"] == "Memory Image"
        assert res9_mem["routed_module"] == "Memory Analysis (Volatility 3)"

        # Test 10: Unsupported Artifact Types (PDF, DOCX, JPG, PNG)
        t10_pdf = os.path.join(test_dir, "report.pdf")
        with open(t10_pdf, "wb") as f:
            f.write(b"%PDF-1.7 header content...")
        res10 = identify_evidence(t10_pdf)
        print("\nTest 10 - Unsupported Artifact Identification (PDF Document):")
        print("  Evidence Type:", res10["evidence_type"])
        print("  Confidence:", res10["confidence"])
        print("  Routed Module:", res10["routed_module"])
        assert res10["evidence_type"] == "PDF Document"
        assert res10["confidence"] == "HIGH"
        assert res10["routed_module"] == "General Analysis only"

        print("\n==================================================")
        print("ALL 10 CONTENT IDENTIFICATION TESTS PASSED SUCCESSFULLY!")
        print("==================================================")

    finally:
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


def test_pipeline_routing_integration():
    print("\n==================================================")
    print("RUNNING PIPELINE ROUTER INTEGRATION TEST FOR UNSUPPORTED ARTIFACT")
    print("==================================================")
    test_dir = tempfile.mkdtemp()
    try:
        pdf_path = os.path.join(test_dir, "sample.pdf")
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4 sample pdf content")
        
        pipe_res = run_automated_analysis(pdf_path)
        print("Status:", pipe_res["status"])
        print("Identified Artifact:", pipe_res["identification"]["evidence_type"])
        print("Confidence:", pipe_res["identification"]["confidence"])
        print("Browser Analysis Status:", pipe_res["module_statuses"].get("Browser Artifact Analysis"))
        print("Event Log Analysis Status:", pipe_res["module_statuses"].get("Event Log Analysis"))
        print("Memory Analysis Status:", pipe_res["module_statuses"].get("Memory Analysis (Volatility 3)"))

        assert pipe_res["status"] == "SUCCESS"
        assert pipe_res["identification"]["evidence_type"] == "PDF Document"
        assert pipe_res["module_statuses"].get("Browser Artifact Analysis") == "NOT_APPLICABLE"
        assert pipe_res["module_statuses"].get("Event Log Analysis") == "NOT_APPLICABLE"
        assert pipe_res["module_statuses"].get("Memory Analysis (Volatility 3)") == "NOT_APPLICABLE"

        print("PIPELINE ROUTER INTEGRATION TEST PASSED!")
    finally:
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    run_identification_tests()
    test_pipeline_routing_integration()
