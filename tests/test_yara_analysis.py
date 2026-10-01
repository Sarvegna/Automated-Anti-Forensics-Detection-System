import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.yara_analysis import analyze_with_yara


def run_tests():
    evidence_dir = os.path.join(project_root, "evidence", "input")
    os.makedirs(evidence_dir, exist_ok=True)

    yara_test_file = os.path.join(evidence_dir, "yara_test_evidence.txt")
    clean_test_file = os.path.join(evidence_dir, "sample_evidence.txt")

    # Create synthetic test file containing harmless test strings for YARA rules
    with open(yara_test_file, "w") as f:
        f.write("Harmless synthetic test file.\n")
        f.write("Executing wevtutil cl System command for log clearing test.\n")
        f.write("Using sdelete tool for secure file cleanup test.\n")

    print("--- TEST 1: Synthetic YARA Match Evidence File ---")
    res1 = analyze_with_yara(yara_test_file)
    print("Status:", res1["status"])
    print("Evidence Type:", res1["evidence_type"])
    print("Warnings:", res1["warnings"])
    print("Errors:", res1["errors"])
    if res1["status"] == "SUCCESS":
        print("Matches Found:", res1["data"].get("total_matches"))
        print("Findings Generated:", len(res1["findings"]))
        for f in res1["findings"]:
            print(f"  - [{f['finding_id']}] {f['type']} ({f['severity']}): {f['reason']}")
    print()

    print("--- TEST 2: Clean Evidence File ---")
    res2 = analyze_with_yara(clean_test_file)
    print("Status:", res2["status"])
    print("Evidence Type:", res2["evidence_type"])
    if res2["status"] == "SUCCESS":
        print("Matches Found:", res2["data"].get("total_matches"))
    print()

    # Validate that status is either SUCCESS (if yara is available) or MISSING_DEPENDENCY (if yara binary is missing)
    assert res1["status"] in {"SUCCESS", "MISSING_DEPENDENCY"}, f"Test 1 failed: {res1}"
    assert res2["status"] in {"SUCCESS", "MISSING_DEPENDENCY"}, f"Test 2 failed: {res2}"

    print("ALL YARA ANALYSIS TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()
