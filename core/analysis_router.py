import os
from core.evidence_object import EvidenceObject, create_evidence_object, identify_source_type
from core.validation import validate_evidence_file
from core.integrity import calculate_sha256
from core.evidence_identifier import identify_evidence
from core.timestamp_analysis import analyze_timestamps
from core.hidden_file_detection import check_hidden_file
from core.evtx_reader import read_evtx_file
from core.eventlog_analysis import analyze_event_log
from core.browser_db_analysis import analyze_browser_database
from core.memory_analysis import analyze_memory_image
from core.ntfs_analysis import analyze_ntfs_image
from core.yara_analysis import analyze_with_yara
from core.risk_scoring import calculate_risk_score
from core.findings import build_findings_from_risk_result


def run_automated_analysis(evidence_input, evidence_reference=None, source_metadata=None):
    """
    Automated Forensic Analysis Pipeline.

    Workflow:
    1. Validation
    2. Identify Source & Create Tagged EvidenceObject
    3. SHA-256 Hash Integrity
    4. Artifact Type Identification
    5. Determine & Run Applicable Analysis Modules
    6. Collect Structured Findings & Aggregate Risk Score
    7. Return Pipeline Result with separate Evidence Context and Structured Findings.
    """
    # 1. Validation & 2. Identify Source / Create EvidenceObject
    if isinstance(evidence_input, EvidenceObject):
        evidence_obj = evidence_input
        file_path = evidence_obj.path
        if evidence_reference is None:
            evidence_reference = evidence_obj.evidence_reference
    else:
        file_path = str(evidence_input)
        if evidence_reference is None:
            evidence_reference = os.path.basename(file_path)

        is_valid, validation_msg = validate_evidence_file(file_path)
        if not is_valid:
            source_type = identify_source_type(file_path)
            return {
                "status": "FAILED",
                "error_message": validation_msg,
                "evidence_reference": evidence_reference,
                "file_path": file_path,
                "sha256": None,
                "source_type": source_type,
                "evidence_context": {
                    "source_type": source_type,
                    "evidence_path": file_path,
                    "sha256": None
                },
                "identification": {"evidence_type": "Invalid File"},
                "applicable_modules": [],
                "module_statuses": {},
                "findings": [],
                "risk_result": {"score": 0, "risk_level": "LOW", "contributing_indicators": []}
            }

        try:
            evidence_obj = create_evidence_object(
                file_path=file_path,
                evidence_reference=evidence_reference,
                source_metadata=source_metadata
            )
        except Exception as e:
            source_type = identify_source_type(file_path)
            return {
                "status": "FAILED",
                "error_message": str(e),
                "evidence_reference": evidence_reference,
                "file_path": file_path,
                "sha256": None,
                "source_type": source_type,
                "evidence_context": {
                    "source_type": source_type,
                    "evidence_path": file_path,
                    "sha256": None
                },
                "identification": {"evidence_type": "Invalid File"},
                "applicable_modules": [],
                "module_statuses": {},
                "findings": [],
                "risk_result": {"score": 0, "risk_level": "LOW", "contributing_indicators": []}
            }

    file_path = evidence_obj.path
    sha256_hash = evidence_obj.sha256
    source_type = evidence_obj.source_type
    if evidence_reference is None:
        evidence_reference = evidence_obj.evidence_reference or os.path.basename(file_path)

    input_method = (source_metadata or {}).get("input_method", "Browser Upload" if (source_metadata or {}).get("is_web_upload") else "Local Evidence Path")
    timestamp_prov = "browser_upload" if (source_metadata or {}).get("is_web_upload") else "local_filesystem"

    # Logically separate Evidence Context
    evidence_context = {
        "source_type": source_type,
        "input_method": input_method,
        "timestamp_provenance": timestamp_prov,
        "evidence_path": file_path,
        "sha256": sha256_hash,
        "hash_algorithm": evidence_obj.hash_algorithm,
        "evidence_reference": evidence_reference
    }

    # 3. Artifact Identification
    identification = identify_evidence(file_path)
    identification["source_type"] = source_type
    ext = identification.get("extension", "").lower()

    # Tracking structures
    applicable_modules = []
    module_statuses = {}
    module_results = {}
    all_findings = []

    # --- Module 1: Timestamp Analysis (Applicable to ALL files) ---
    applicable_modules.append("Timestamp Analysis")
    try:
        timestamp_result = analyze_timestamps(evidence_obj, source_metadata=source_metadata)
        module_statuses["Timestamp Analysis"] = "SUCCESS"
        module_results["Timestamp Analysis"] = timestamp_result
    except Exception as e:
        timestamp_result = None
        module_statuses["Timestamp Analysis"] = "FAILED"
        module_results["Timestamp Analysis"] = {"error": str(e)}

    # --- Module 2: Hidden File Check (Applicable to ALL files) ---
    applicable_modules.append("Hidden File Check")
    try:
        hidden_file_result = check_hidden_file(evidence_obj)
        module_statuses["Hidden File Check"] = "SUCCESS"
        module_results["Hidden File Check"] = hidden_file_result
    except Exception as e:
        hidden_file_result = None
        module_statuses["Hidden File Check"] = "FAILED"
        module_results["Hidden File Check"] = {"error": str(e)}

    # --- Module 3: YARA Cross-Artifact Analysis (Applicable to ALL files) ---
    applicable_modules.append("YARA Analysis")
    yara_result = analyze_with_yara(file_path, evidence_reference=evidence_reference)
    module_statuses["YARA Analysis"] = yara_result.get("status", "FAILED")
    module_results["YARA Analysis"] = yara_result
    if yara_result.get("findings"):
        all_findings.extend(yara_result["findings"])

    # --- Module 4: Windows Event Log Analysis ---
    eventlog_result = None
    is_evtx_target = (
        identification.get("routed_module") == "Event Log Analysis"
        or identification.get("evidence_type") in ("Windows Event Log", "Windows Event Log Candidate")
    )
    if is_evtx_target:
        applicable_modules.append("Event Log Analysis")
        try:
            events = read_evtx_file(file_path)
            eventlog_result = analyze_event_log(events)
            module_statuses["Event Log Analysis"] = "SUCCESS"
            module_results["Event Log Analysis"] = eventlog_result
        except Exception as e:
            module_statuses["Event Log Analysis"] = "FAILED"
            module_results["Event Log Analysis"] = {"error": str(e)}
    else:
        module_statuses["Event Log Analysis"] = "NOT_APPLICABLE"

    # --- Module 5: Browser Database Analysis ---
    browser_db_result = None
    is_browser_candidate = (
        identification.get("routed_module") == "Browser Artifact Analysis"
        or (
            ext in {".db", ".sqlite", ".sqlite3", ".db3"}
            and identification.get("evidence_type") not in {"SQLite Database (Non-Browser)", "General File", "Corrupted SQLite Database"}
            and identification.get("detected_format") == "SQLite"
        )
    )

    print("\n[DEBUG] --- BROWSER ARTIFACT ANALYSIS ROUTER CHECK ---")
    print(f"[DEBUG] file_path: {file_path}")
    print(f"[DEBUG] filename (evidence_reference): {evidence_reference}")
    print(f"[DEBUG] extension: {ext}")
    print(f"[DEBUG] identification result: {identification}")
    print(f"[DEBUG] evidence_type: {identification.get('evidence_type')}")
    print(f"[DEBUG] router condition evaluated: {is_browser_candidate}")

    if is_browser_candidate:
        applicable_modules.append("Browser Artifact Analysis")
        browser_db_result = analyze_browser_database(file_path, evidence_reference=evidence_reference)
        module_statuses["Browser Artifact Analysis"] = browser_db_result.get("status", "NOT_APPLICABLE")
        module_results["Browser Artifact Analysis"] = browser_db_result

        # Update identification evidence_type with refined classification if schema detected
        if browser_db_result.get("evidence_type") in {"Browser Database (Chromium)", "SQLite Database (Non-Browser)", "Corrupted SQLite Database"}:
            identification["evidence_type"] = browser_db_result["evidence_type"]

        if browser_db_result.get("findings"):
            all_findings.extend(browser_db_result["findings"])

        print(f"[DEBUG] browser_db_result: {browser_db_result}")
        print(f"[DEBUG] browser_db_result['status']: {browser_db_result.get('status')}")
        print(f"[DEBUG] browser_db_result['warnings']: {browser_db_result.get('warnings')}")
        print(f"[DEBUG] browser_db_result['errors']: {browser_db_result.get('errors')}")
        print(f"[DEBUG] browser_db_result['metadata']: {browser_db_result.get('metadata')}\n")
    else:
        module_statuses["Browser Artifact Analysis"] = "NOT_APPLICABLE"

    # --- Module 6: Memory Analysis (Volatility 3) ---
    memory_result = None
    is_memory_target = (
        identification.get("routed_module") == "Memory Analysis (Volatility 3)"
        or identification.get("evidence_type") in ("Memory Image", "Memory Image Candidate")
    )
    if is_memory_target:
        applicable_modules.append("Memory Analysis (Volatility 3)")
        memory_result = analyze_memory_image(file_path, evidence_reference=evidence_reference)
        module_statuses["Memory Analysis (Volatility 3)"] = memory_result.get("status", "UNSUPPORTED")
        module_results["Memory Analysis (Volatility 3)"] = memory_result
        if memory_result.get("findings"):
            all_findings.extend(memory_result["findings"])
    else:
        module_statuses["Memory Analysis (Volatility 3)"] = "NOT_APPLICABLE"

    # --- Module 7: NTFS Artifact Analysis ---
    ntfs_result = None
    is_ntfs_target = (
        identification.get("routed_module") == "NTFS Artifact Analysis"
        or identification.get("evidence_type") in ("NTFS Forensic Image", "NTFS Disk Image")
    )
    if is_ntfs_target:
        applicable_modules.append("NTFS Artifact Analysis")
        ntfs_result = analyze_ntfs_image(evidence_obj, evidence_reference=evidence_reference)
        module_statuses["NTFS Artifact Analysis"] = ntfs_result.get("status", "FAILED")
        module_results["NTFS Artifact Analysis"] = ntfs_result
        if ntfs_result.get("findings"):
            all_findings.extend(ntfs_result["findings"])
    else:
        module_statuses["NTFS Artifact Analysis"] = "NOT_APPLICABLE"

    # --- Risk Scoring Aggregation ---
    # Construct browser result wrapper for risk scoring if browser DB returned gaps
    browser_scoring_result = None
    if browser_db_result and browser_db_result.get("data", {}).get("gap_indicators"):
        browser_scoring_result = {
            "anomaly_detected": True,
            "indicators": browser_db_result["data"]["gap_indicators"]
        }

    risk_result = calculate_risk_score(
        timestamp_result=timestamp_result,
        eventlog_result=eventlog_result,
        browser_result=browser_scoring_result,
        hidden_file_result=hidden_file_result,
        ntfs_result=ntfs_result
    )

    # Generate structured findings from risk scoring result
    risk_findings = build_findings_from_risk_result(risk_result, evidence_reference)

    # Deduplicate findings by finding_id / type
    existing_types = {f["type"] for f in all_findings}
    for rf in risk_findings:
        if rf["type"] not in existing_types:
            all_findings.append(rf)
            existing_types.add(rf["type"])

    return {
        "status": "SUCCESS",
        "evidence_reference": evidence_reference,
        "file_path": file_path,
        "sha256": sha256_hash,
        "source_type": source_type,
        "evidence_object": evidence_obj.to_dict(),
        "evidence_context": evidence_context,
        "identification": identification,
        "applicable_modules": applicable_modules,
        "module_statuses": module_statuses,
        "module_results": module_results,
        "timestamp_result": timestamp_result,
        "hidden_file_result": hidden_file_result,
        "eventlog_result": eventlog_result,
        "browser_result": browser_db_result,
        "memory_result": memory_result,
        "ntfs_result": ntfs_result,
        "yara_result": yara_result,
        "risk_result": risk_result,
        "findings": all_findings
    }