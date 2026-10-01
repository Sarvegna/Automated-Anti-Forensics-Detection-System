import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.analysis_router import run_automated_analysis


def run_pipeline_tests():
    evidence_dir = os.path.join(project_root, "evidence", "input")

    test_files = [
        ("Generic Text File", os.path.join(evidence_dir, "sample_evidence.txt")),
        ("Browser History DB", os.path.join(evidence_dir, "synthetic_browser_history.db")),
        ("Timestomped File", os.path.join(evidence_dir, "anomaly_test.txt")),
        ("YARA Match File", os.path.join(evidence_dir, "yara_test_evidence.txt")),
    ]

    for label, filepath in test_files:
        print(f"==================================================")
        print(f"PIPELINE TEST: {label} ({os.path.basename(filepath)})")
        print(f"==================================================")

        res = run_automated_analysis(filepath)

        print("Pipeline Status:", res["status"])
        print("SHA-256 Hash:", res["sha256"])
        print("Identified Artifact:", res["identification"]["evidence_type"])
        print("Applicable Modules:", res["applicable_modules"])
        print("Module Statuses:")
        for mod, st in res["module_statuses"].items():
            print(f"  - {mod}: {st}")

        print(f"Risk Score: {res['risk_result']['score']} / {res['risk_result']['risk_level']}")
        print(f"Total Structured Findings: {len(res['findings'])}")
        for f in res["findings"]:
            print(f"  - [{f['finding_id']}] {f['type']} ({f['severity']}): {f['reason'][:80]}...")
        print()

    print("ALL PIPELINE ROUTER INTEGRATION TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    run_pipeline_tests()