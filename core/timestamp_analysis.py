import os
from datetime import datetime, timezone
from core.evidence_object import identify_source_type

# Tolerance threshold (2.0 seconds) to account for FAT32 2-second timestamp resolution,
# file copy/stream creation buffering, and sub-second float precision differences.
TOLERANCE_SECONDS = 2.0


def analyze_timestamps(evidence_input, source_metadata=None):
    """
    Reads a file's Created, Modified, and Accessed timestamps (in UTC),
    or uses explicit source_metadata (for web upload streams where client ctime is unavailable).

    Accepts either an EvidenceObject or a direct file path string.

    Performs robust numerical comparison against anti-forensics anomalies:
    - Modified Before Created (with > 2.0s tolerance)
    - Accessed Before Created (with > 2.0s tolerance)
    - Future Timestamp (relative to UTC current time + 2.0s tolerance)

    Prints exact compared values for forensic traceability and debugging.
    """
    if hasattr(evidence_input, "path") and hasattr(evidence_input, "source_type"):
        file_path = evidence_input.path
        source_type = evidence_input.source_type
        if source_metadata is None:
            source_metadata = getattr(evidence_input, "source_metadata", None)
    else:
        file_path = str(evidence_input)
        source_type = identify_source_type(file_path)

    is_web_upload = source_metadata.get("is_web_upload", False) if source_metadata else False

    if is_web_upload:
        # Web upload stream: Client OS creation time (ctime) is NOT transmitted over browser HTTP.
        # Do NOT fake ctime using server temporary upload creation time.
        created_raw = None
        created_dt = None

        # Modified time: Use browser last_modified if provided in source_metadata, else read file mtime
        if source_metadata and source_metadata.get("last_modified"):
            modified_dt = source_metadata["last_modified"]
            if isinstance(modified_dt, (int, float)):
                modified_raw = float(modified_dt)
                modified_dt = datetime.fromtimestamp(modified_raw, tz=timezone.utc)
            elif isinstance(modified_dt, datetime):
                if modified_dt.tzinfo is None:
                    modified_dt = modified_dt.replace(tzinfo=timezone.utc)
                modified_raw = modified_dt.timestamp()
            else:
                modified_raw = os.path.getmtime(file_path)
                modified_dt = datetime.fromtimestamp(modified_raw, tz=timezone.utc)
        else:
            modified_raw = os.path.getmtime(file_path)
            modified_dt = datetime.fromtimestamp(modified_raw, tz=timezone.utc)

        accessed_raw = None
        accessed_dt = None
    else:
        # Direct local file analysis: Read native OS filesystem metadata without modifying evidence file
        created_raw = os.path.getctime(file_path)
        modified_raw = os.path.getmtime(file_path)
        accessed_raw = os.path.getatime(file_path)

        created_dt = datetime.fromtimestamp(created_raw, tz=timezone.utc)
        modified_dt = datetime.fromtimestamp(modified_raw, tz=timezone.utc)
        accessed_dt = datetime.fromtimestamp(accessed_raw, tz=timezone.utc)

    now_raw = datetime.now(timezone.utc).timestamp()
    now_dt = datetime.fromtimestamp(now_raw, tz=timezone.utc)

    # Detailed debugging output showing exact compared float values and microsecond precision
    print("\n[DEBUG] --- TIMESTAMP NUMERICAL COMPARISON CHECK ---")
    print(f"[DEBUG] File Path: {file_path}")
    print(f"[DEBUG] Source Type: {source_type}")
    if created_dt:
        print(f"[DEBUG] Created : {created_dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC (raw float: {created_raw:.6f})")
    else:
        print("[DEBUG] Created : Unavailable (Web Upload Stream)")

    if modified_dt:
        print(f"[DEBUG] Modified: {modified_dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC (raw float: {modified_raw:.6f})")
    else:
        print("[DEBUG] Modified: Unavailable")

    if accessed_dt:
        print(f"[DEBUG] Accessed: {accessed_dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC (raw float: {accessed_raw:.6f})")
    else:
        print("[DEBUG] Accessed: Unavailable")

    print(f"[DEBUG] System  : {now_dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC (raw float: {now_raw:.6f})")
    print(f"[DEBUG] Tolerance Threshold: > {TOLERANCE_SECONDS}s")

    indicators = []

    # Check 1: Modified < Created (Modified time is earlier than Created time by more than TOLERANCE_SECONDS)
    if created_raw is not None and modified_raw is not None:
        mod_created_diff = created_raw - modified_raw
        print(f"[DEBUG] Check 1 (Modified < Created): created_raw - modified_raw = {mod_created_diff:.6f}s (Trigger if > {TOLERANCE_SECONDS}s)")
        if mod_created_diff > TOLERANCE_SECONDS:
            indicators.append({
                "type": "Modified Before Created",
                "explanation": (
                    f"Potential anti-forensic indicator: Modified timestamp ({modified_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                    f"is earlier than Created timestamp ({created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                    f"by {mod_created_diff:.2f} seconds (exceeding tolerance of {TOLERANCE_SECONDS}s). Requires investigator review."
                )
            })

    # Check 2: Accessed < Created (Accessed time is earlier than Created time by more than TOLERANCE_SECONDS)
    if created_raw is not None and accessed_raw is not None:
        acc_created_diff = created_raw - accessed_raw
        print(f"[DEBUG] Check 2 (Accessed < Created): created_raw - accessed_raw = {acc_created_diff:.6f}s (Trigger if > {TOLERANCE_SECONDS}s)")
        if acc_created_diff > TOLERANCE_SECONDS:
            indicators.append({
                "type": "Accessed Before Created",
                "explanation": (
                    f"Potential anti-forensic indicator: Accessed timestamp ({accessed_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                    f"is earlier than Created timestamp ({created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                    f"by {acc_created_diff:.2f} seconds (exceeding tolerance of {TOLERANCE_SECONDS}s). Requires investigator review."
                )
            })

    # Check 3: Future Timestamps (Any timestamp is ahead of system time by more than TOLERANCE_SECONDS)
    future_details = []
    if created_raw is not None and (created_raw - now_raw) > TOLERANCE_SECONDS:
        days = int((created_raw - now_raw) / 86400)
        days_str = f"approximately {days} days" if days > 0 else f"{int(created_raw - now_raw)}s"
        future_details.append(f"Created timestamp ({created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) is {days_str} in the future")
    if modified_raw is not None and (modified_raw - now_raw) > TOLERANCE_SECONDS:
        days = int((modified_raw - now_raw) / 86400)
        days_str = f"approximately {days} days" if days > 0 else f"{int(modified_raw - now_raw)}s"
        future_details.append(f"Modified timestamp ({modified_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) is {days_str} in the future")
    if accessed_raw is not None and (accessed_raw - now_raw) > TOLERANCE_SECONDS:
        days = int((accessed_raw - now_raw) / 86400)
        days_str = f"approximately {days} days" if days > 0 else f"{int(accessed_raw - now_raw)}s"
        future_details.append(f"Accessed timestamp ({accessed_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) is {days_str} in the future")

    if future_details:
        indicators.append({
            "type": "Future Timestamp",
            "explanation": (
                f"Potential anti-forensic indicator: {'; '.join(future_details)} relative to the analysis reference time. "
                f"Requires investigator review."
            )
        })

    # Check 4: Accessed < Modified (when Created is unavailable)
    if modified_raw is not None and accessed_raw is not None and created_raw is None:
        acc_mod_diff = modified_raw - accessed_raw
        if acc_mod_diff > TOLERANCE_SECONDS:
            indicators.append({
                "type": "Accessed Before Modified",
                "explanation": (
                    f"Potential anti-forensic indicator: Accessed timestamp ({accessed_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                    f"is earlier than Modified timestamp ({modified_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
                    f"by {acc_mod_diff:.2f} seconds (exceeding tolerance of {TOLERANCE_SECONDS}s). Requires investigator review."
                )
            })

    print(f"[DEBUG] Anomaly Detected: {len(indicators) > 0}")
    if indicators:
        for ind in indicators:
            print(f"[DEBUG]   - [{ind['type']}] {ind['explanation']}")
    print()

    if is_web_upload:
        provenance_category = "browser_upload"
        provenance_desc = "Browser upload timestamp (client ctime unavailable over HTTP)"
    else:
        provenance_category = "local_filesystem"
        provenance_desc = (
            "Local filesystem timestamp from forensic image"
            if source_type == "forensic_image"
            else "Local filesystem timestamp from individual evidence file"
        )

    return {
        "file_path": file_path,
        "source_type": source_type,
        "timestamp_provenance": {
            "category": provenance_category,
            "source_type": source_type,
            "description": provenance_desc
        },
        "created": created_dt,
        "modified": modified_dt,
        "accessed": accessed_dt,
        "created_raw": created_raw,
        "modified_raw": modified_raw,
        "accessed_raw": accessed_raw,
        "indicators": indicators,
        "anomaly_detected": len(indicators) > 0
    }