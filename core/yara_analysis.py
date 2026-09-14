import os
from core.findings import create_finding


def analyze_with_yara(file_path, rules_path=None, evidence_reference=None):
    """
    Performs YARA cross-artifact rule scanning on evidence files.

    Returns a standardized ModuleResult dictionary:
    {
        "module_name": "YARA Analysis",
        "status": "SUCCESS" | "MISSING_DEPENDENCY" | "FAILED" | "NOT_APPLICABLE",
        "evidence_type": "Cross-Artifact",
        "findings": [...],
        "data": {...},
        "warnings": [...],
        "errors": [...],
        "metadata": {...}
    }
    """
    if evidence_reference is None:
        evidence_reference = os.path.basename(file_path)

    # 1. Attempt to import yara library (strict requirement per user directive)
    try:
        import yara
    except ImportError:
        return {
            "module_name": "YARA Analysis",
            "status": "MISSING_DEPENDENCY",
            "evidence_type": "Cross-Artifact",
            "findings": [],
            "data": {},
            "warnings": [
                "YARA Python module ('yara-python') is not installed or compiled in the runtime environment. "
                "YARA cross-artifact scanning requires the native 'yara' library."
            ],
            "errors": ["ModuleNotFoundError: No module named 'yara'"],
            "metadata": {"file_path": file_path}
        }

    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return {
            "module_name": "YARA Analysis",
            "status": "NOT_APPLICABLE",
            "evidence_type": "Empty or Missing File",
            "findings": [],
            "data": {},
            "warnings": ["Evidence file does not exist or is empty."],
            "errors": [],
            "metadata": {"file_path": file_path}
        }

    # Determine YARA rules path
    if rules_path is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_path = os.path.join(project_root, "rules", "yara", "anti_forensics.yar")

    if not os.path.exists(rules_path):
        return {
            "module_name": "YARA Analysis",
            "status": "FAILED",
            "evidence_type": "Cross-Artifact",
            "findings": [],
            "data": {},
            "warnings": [],
            "errors": [f"YARA rules file not found at path: {rules_path}"],
            "metadata": {"file_path": file_path, "rules_path": rules_path}
        }

    try:
        # 2. Compile YARA rules
        compiled_rules = yara.compile(filepath=rules_path)

        # 3. Perform scan on evidence file
        matches = compiled_rules.match(file_path)

        matched_rules = []
        findings = []

        for match in matches:
            rule_name = match.rule
            meta = match.meta or {}
            severity = meta.get("severity", "MEDIUM")
            description = meta.get("description", "Potential anti-forensic indicator detected by YARA rule match.")

            matched_rules.append({
                "rule": rule_name,
                "meta": meta,
                "tags": match.tags
            })

            # Create structured finding
            explanation = (
                f"YARA Match Indicator: '{rule_name}'. {description} "
                "Observation: This is a signature indicator requiring investigator review and context interpretation, "
                "not definitive proof of malicious intent."
            )

            finding = create_finding(
                finding_type=f"YARA Match ({rule_name})",
                severity=severity,
                evidence_reference=evidence_reference,
                reason=explanation,
                source="YARA Analysis"
            )
            findings.append(finding)

        return {
            "module_name": "YARA Analysis",
            "status": "SUCCESS",
            "evidence_type": "Cross-Artifact",
            "findings": findings,
            "data": {
                "total_matches": len(matches),
                "matched_rules": matched_rules
            },
            "warnings": [],
            "errors": [],
            "metadata": {
                "file_path": file_path,
                "rules_path": rules_path
            }
        }

    except Exception as e:
        return {
            "module_name": "YARA Analysis",
            "status": "FAILED",
            "evidence_type": "Cross-Artifact",
            "findings": [],
            "data": {},
            "warnings": [],
            "errors": [f"YARA scanning error: {str(e)}"],
            "metadata": {"file_path": file_path, "rules_path": rules_path}
        }
