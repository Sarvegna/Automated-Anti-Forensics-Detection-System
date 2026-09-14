import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.memory_analysis import analyze_memory_image


def run_tests():
    evidence_dir = os.path.join(project_root, "evidence", "input")
    os.makedirs(evidence_dir, exist_ok=True)

    non_mem_file = os.path.join(evidence_dir, "sample_evidence.txt")
    mem_file = os.path.join(evidence_dir, "synthetic_memory.raw")

    # Create dummy raw file for testing missing dependency / unsupported handling
    if not os.path.exists(mem_file):
        with open(mem_file, "wb") as f:
            f.write(b"\x00" * 4096)

    print("--- TEST 1: Non-Memory Evidence File (.txt) ---")
    res1 = analyze_memory_image(non_mem_file)
    print("Status:", res1["status"])
    print("Evidence Type:", res1["evidence_type"])
    print("Warnings:", res1["warnings"])
    print()

    print("--- TEST 2: Memory Candidate (.raw) ---")
    res2 = analyze_memory_image(mem_file)
    print("Status:", res2["status"])
    print("Evidence Type:", res2["evidence_type"])
    print("Warnings:", res2["warnings"])
    print("Errors:", res2["errors"])
    print()

    assert res1["status"] == "NOT_APPLICABLE", f"Test 1 failed: {res1}"
    assert res2["status"] in {"MISSING_DEPENDENCY", "UNSUPPORTED", "SUCCESS"}, f"Test 2 unexpected status: {res2['status']}"

    print("ALL MEMORY ANALYSIS TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()
