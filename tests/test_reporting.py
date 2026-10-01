import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.reporting import generate_json_report, generate_html_report


def run_tests():
    output_dir = os.path.join(project_root, "evidence", "input")

    mock_pipeline_result = {
        "evidence_reference": "synthetic_browser_history.db",
        "file_path": "c:/evidence/synthetic_browser_history.db",
        "sha256": "ccec7bb2809e5f54bcc4aa9c2c4234dc7c9620cd34aa90067061c27553da49c9",
        "identification": {"evidence_type": "Browser Database (Chromium)"},
        "applicable_modules": ["Timestamp Analysis", "Hidden File Check", "Browser Artifact Analysis", "YARA Analysis"],
        "module_statuses": {
            "Timestamp Analysis": "SUCCESS",
            "Hidden File Check": "SUCCESS",
            "Browser Artifact Analysis": "SUCCESS",
            "YARA Analysis": "MISSING_DEPENDENCY",
            "Memory Analysis (Volatility 3)": "NOT_APPLICABLE"
        },
        "risk_result": {
            "score": 45,
            "risk_level": "MEDIUM"
        },
        "findings": [
            {
                "finding_id": "AF-607C5FE2",
                "type": "Timeline Gap (Browser)",
                "severity": "MEDIUM",
                "evidence": "synthetic_browser_history.db",
                "reason": "Potential anti-forensic indicator: a gap of 50.0 minutes was found between consecutive entries.",
                "source": "Browser History"
            }
        ]
    }

    case_info = {
        "case_id": "CASE-20260802-9901",
        "evidence_id": "EVID-A1B2C3",
        "analyst": "Investigator Sarvegna"
    }

    json_path = os.path.join(output_dir, "test_report.json")
    html_path = os.path.join(output_dir, "test_report.html")

    json_out = generate_json_report(mock_pipeline_result, case_info, output_path=json_path)
    html_out = generate_html_report(mock_pipeline_result, case_info, output_path=html_path)

    print("--- TEST 1: JSON Report Generation ---")
    print("Generated JSON characters:", len(json_out))
    print("JSON Report saved to:", json_path)
    print()

    print("--- TEST 2: HTML Report Generation ---")
    print("Generated HTML characters:", len(html_out))
    print("HTML Report saved to:", html_path)
    print()

    assert os.path.exists(json_path) and os.path.getsize(json_path) > 0
    assert os.path.exists(html_path) and os.path.getsize(html_path) > 0

    print("ALL REPORTING TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()
