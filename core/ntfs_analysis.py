import os
import struct
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

TOLERANCE_SECONDS = 2.0


def filetime_to_dt(ft: int) -> Optional[datetime]:
    """
    Converts 64-bit Windows FILETIME (100-ns intervals since 1601-01-01 00:00:00 UTC)
    to a Python UTC datetime object. Returns None if ft is zero or out of valid range.
    """
    if not ft or ft <= 0:
        return None
    try:
        # Windows epoch offset: 11644473600 seconds between 1601-01-01 and 1970-01-01
        timestamp_sec = (ft - 116444736000000000) / 10000000.0
        return datetime.fromtimestamp(timestamp_sec, tz=timezone.utc)
    except Exception:
        return None


def find_ntfs_volume(file_path: str) -> Dict[str, Any]:
    """
    Inspects a file or disk image in read-only mode to locate and validate an NTFS volume.
    Scans offset 0 as well as MBR/GPT partition tables.
    Validates essential NTFS BPB parameters.
    """
    if not os.path.isfile(file_path):
        return {"is_ntfs": False, "reason": "File does not exist."}

    try:
        with open(file_path, "rb") as f:
            # Read first 512 bytes
            boot_sector = f.read(512)
            if len(boot_sector) < 512:
                return {"is_ntfs": False, "reason": "File too small for boot sector."}

            candidate_offsets = []

            # 1. Check offset 0
            if boot_sector[3:11] == b"NTFS    ":
                candidate_offsets.append(0)

            # 2. Check MBR partition table (if MBR signature 0x55AA at offset 510)
            if boot_sector[510:512] == b"\x55\xaa":
                for i in range(4):
                    entry = boot_sector[446 + i * 16 : 446 + (i + 1) * 16]
                    part_type = entry[4]
                    lba_start = struct.unpack("<I", entry[8:12])[0]
                    num_sectors = struct.unpack("<I", entry[12:16])[0]
                    if part_type in (0x07, 0x00) and lba_start > 0:
                        part_offset = lba_start * 512
                        candidate_offsets.append(part_offset)

            # Deduplicate offsets preserving order
            candidate_offsets = list(dict.fromkeys(candidate_offsets))

            # Validate candidate offsets against NTFS BPB fields
            for offset in candidate_offsets:
                f.seek(offset)
                vbr = f.read(512)
                if len(vbr) < 512 or vbr[3:11] != b"NTFS    ":
                    continue

                bytes_per_sec = struct.unpack("<H", vbr[11:13])[0]
                sec_per_cluster = vbr[13]
                mft_lcn = struct.unpack("<Q", vbr[48:56])[0]
                clusters_per_mft_record = struct.unpack("<b", vbr[64:65])[0]

                # Validate essential BPB parameters
                if bytes_per_sec not in (512, 1024, 2048, 4096) or sec_per_cluster == 0:
                    continue

                cluster_size = bytes_per_sec * sec_per_cluster
                if clusters_per_mft_record < 0:
                    mft_record_size = 1 << (-clusters_per_mft_record)
                else:
                    mft_record_size = clusters_per_mft_record * cluster_size

                mft_offset = offset + (mft_lcn * cluster_size)

                # Verify MFT record 0 magic
                f.seek(mft_offset)
                mft0_header = f.read(4)
                if mft0_header == b"FILE":
                    return {
                        "is_ntfs": True,
                        "part_offset": offset,
                        "bytes_per_sec": bytes_per_sec,
                        "sec_per_cluster": sec_per_cluster,
                        "cluster_size": cluster_size,
                        "mft_lcn": mft_lcn,
                        "mft_offset": mft_offset,
                        "mft_record_size": mft_record_size,
                    }

    except Exception as e:
        return {"is_ntfs": False, "reason": f"Error scanning NTFS volume: {str(e)}"}

    return {"is_ntfs": False, "reason": "No valid NTFS volume found."}


def parse_mft_entry(data: bytes, record_num: int) -> Optional[Dict[str, Any]]:
    """
    Parses a single MFT record data buffer (typically 1024 bytes).
    Applies Update Sequence Array (USA) fixups and extracts resident $STANDARD_INFORMATION
    and $FILE_NAME attributes.
    """
    if len(data) < 42 or data[:4] != b"FILE":
        return None

    try:
        update_seq_offset = struct.unpack("<H", data[4:6])[0]
        update_seq_count = struct.unpack("<H", data[6:8])[0]
        first_attr_offset = struct.unpack("<H", data[20:22])[0]
        flags = struct.unpack("<H", data[22:24])[0]
        is_in_use = bool(flags & 1)
        is_dir = bool(flags & 2)

        # Apply USA fixups
        if update_seq_count > 0 and update_seq_offset + update_seq_count * 2 <= len(data):
            raw = bytearray(data)
            usa_num = raw[update_seq_offset : update_seq_offset + 2]
            for i in range(1, update_seq_count):
                sector_offset = i * 512 - 2
                fixup_offset = update_seq_offset + i * 2
                if sector_offset + 2 <= len(raw) and raw[sector_offset : sector_offset + 2] == usa_num:
                    raw[sector_offset : sector_offset + 2] = raw[fixup_offset : fixup_offset + 2]
            data = bytes(raw)

        si = None
        fn_list = []

        curr = first_attr_offset
        while curr < len(data) - 8:
            attr_type = struct.unpack("<I", data[curr : curr + 4])[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack("<I", data[curr + 4 : curr + 8])[0]
            if attr_len == 0 or curr + attr_len > len(data):
                break

            non_resident = data[curr + 8]
            if not non_resident and curr + 22 <= len(data):
                val_len = struct.unpack("<I", data[curr + 16 : curr + 20])[0]
                val_offset = struct.unpack("<H", data[curr + 20 : curr + 22])[0]
                attr_data = data[curr + val_offset : curr + val_offset + val_len]

                if attr_type == 0x10 and len(attr_data) >= 32:
                    c_ft, m_ft, mft_ft, a_ft = struct.unpack("<QQQQ", attr_data[:32])
                    si = {
                        "ctime": filetime_to_dt(c_ft),
                        "mtime": filetime_to_dt(m_ft),
                        "mfttime": filetime_to_dt(mft_ft),
                        "atime": filetime_to_dt(a_ft),
                        "ctime_raw": c_ft,
                        "mtime_raw": m_ft,
                        "mfttime_raw": mft_ft,
                        "atime_raw": a_ft,
                    }
                elif attr_type == 0x30 and len(attr_data) >= 66:
                    parent_ref = struct.unpack("<Q", attr_data[:8])[0] & 0x0000FFFFFFFFFFFF
                    c_ft, m_ft, mft_ft, a_ft = struct.unpack("<QQQQ", attr_data[8:40])
                    fn_name_len = attr_data[64]
                    fn_namespace = attr_data[65]
                    name_bytes = attr_data[66 : 66 + fn_name_len * 2]
                    try:
                        fn_name = name_bytes.decode("utf-16le")
                    except Exception:
                        fn_name = str(name_bytes)
                    fn_list.append({
                        "name": fn_name,
                        "parent_ref": parent_ref,
                        "namespace": fn_namespace,
                        "ctime": filetime_to_dt(c_ft),
                        "mtime": filetime_to_dt(m_ft),
                        "mfttime": filetime_to_dt(mft_ft),
                        "atime": filetime_to_dt(a_ft),
                        "ctime_raw": c_ft,
                        "mtime_raw": m_ft,
                        "mfttime_raw": mft_ft,
                        "atime_raw": a_ft,
                    })

            curr += attr_len

        return {
            "record_num": record_num,
            "is_in_use": is_in_use,
            "is_dir": is_dir,
            "si": si,
            "fn_list": fn_list,
        }
    except Exception:
        return None


def enumerate_ntfs_files(image_path: str, max_records: int = 2000) -> Dict[str, Any]:
    """
    Scans the NTFS MFT in read-only mode, resolves parent directory relationships,
    and returns a structured catalog of internal files with $STANDARD_INFORMATION and $FILE_NAME metadata.
    """
    vol_info = find_ntfs_volume(image_path)
    if not vol_info.get("is_ntfs"):
        return {"status": "FAILED", "reason": vol_info.get("reason", "Not an NTFS volume")}

    mft_offset = vol_info["mft_offset"]
    mft_record_size = vol_info["mft_record_size"]

    records_by_num = {}
    try:
        with open(image_path, "rb") as f:
            f.seek(mft_offset)
            for record_idx in range(max_records):
                data = f.read(mft_record_size)
                if len(data) < mft_record_size:
                    break
                entry = parse_mft_entry(data, record_idx)
                if entry and entry["is_in_use"]:
                    records_by_num[record_idx] = entry

        # Build directory map: record_num -> directory name
        dir_names = {5: ""} # Root directory (MFT #5)
        for num, entry in records_by_num.items():
            if entry["is_dir"] and entry["fn_list"]:
                # Pick non-DOS namespace if available
                win_fn = next((fn for fn in entry["fn_list"] if fn["namespace"] != 2 and fn["name"] not in (".", "$I30")), entry["fn_list"][0])
                if win_fn["name"] and win_fn["name"] not in (".", "$I30"):
                    dir_names[num] = win_fn["name"]

        # Build file list
        files = []
        for num, entry in records_by_num.items():
            if not entry["fn_list"]:
                continue

            best_fn = next((fn for fn in entry["fn_list"] if fn["namespace"] != 2 and fn["name"] not in (".", "$I30")), entry["fn_list"][0])
            name = best_fn["name"]

            # Ignore system metadata files starting with $ or empty names
            if not name or name.startswith("$") or name in (".", "$I30"):
                continue

            parent_ref = best_fn["parent_ref"]
            parent_dir = dir_names.get(parent_ref, "")
            relative_path = f"{parent_dir}/{name}".strip("/") if parent_dir else name

            files.append({
                "record_num": num,
                "is_dir": entry["is_dir"],
                "name": name,
                "relative_path": relative_path,
                "parent_ref": parent_ref,
                "si": entry["si"],
                "fn": best_fn,
                "all_fn": entry["fn_list"],
            })

        return {
            "status": "SUCCESS",
            "volume_info": vol_info,
            "files": files,
            "records_scanned": len(records_by_num),
        }
    except Exception as e:
        return {"status": "FAILED", "reason": f"Error enumerating MFT: {str(e)}"}


def analyze_ntfs_image(evidence_input: Any, evidence_reference: Optional[str] = None) -> Dict[str, Any]:
    """
    Main entry point for NTFS Forensic Image Analysis.
    Enumerates internal files, compares $STANDARD_INFORMATION vs $FILE_NAME timestamps,
    and returns forensic indicators and findings for timestamp discrepancies.
    """
    if hasattr(evidence_input, "path"):
        file_path = evidence_input.path
        if evidence_reference is None:
            evidence_reference = getattr(evidence_input, "evidence_reference", os.path.basename(file_path))
    else:
        file_path = str(evidence_input)
        if evidence_reference is None:
            evidence_reference = os.path.basename(file_path)

    enum_result = enumerate_ntfs_files(file_path)
    if enum_result.get("status") != "SUCCESS":
        return {
            "status": "FAILED",
            "error_message": enum_result.get("reason", "NTFS parsing failed"),
            "evidence_reference": evidence_reference,
            "file_path": file_path,
            "evidence_type": "NTFS Forensic Image",
            "files": [],
            "indicators": [],
            "findings": [],
            "anomaly_detected": False,
        }

    files = enum_result["files"]
    indicators = []
    findings = []
    discrepancies = []

    for file_item in files:
        rel_path = file_item["relative_path"]
        si = file_item.get("si")
        fn = file_item.get("fn")

        if not si or not fn:
            continue

        field_diffs = []
        for field in ("ctime", "mtime", "atime"):
            si_dt = si.get(field)
            fn_dt = fn.get(field)
            si_raw = si.get(f"{field}_raw")
            fn_raw = fn.get(f"{field}_raw")

            if si_raw and fn_raw and si_dt and fn_dt:
                diff_sec = abs((si_raw - fn_raw) / 10000000.0)
                if diff_sec > TOLERANCE_SECONDS:
                    field_name = "Created" if field == "ctime" else ("Modified" if field == "mtime" else "Accessed")
                    field_diffs.append({
                        "field": field_name,
                        "si_dt": si_dt,
                        "fn_dt": fn_dt,
                        "diff_sec": diff_sec,
                    })

        if field_diffs:
            details_str = "; ".join([
                f"{d['field']} ($STANDARD_INFORMATION: {d['si_dt'].strftime('%Y-%m-%d %H:%M:%S UTC')} vs $FILE_NAME: {d['fn_dt'].strftime('%Y-%m-%d %H:%M:%S UTC')}, diff: {d['diff_sec']:.2f}s)"
                for d in field_diffs
            ])
            explanation = (
                f"Potential anti-forensic indicator: NTFS timestamp attribute discrepancy detected for internal file '{rel_path}'. "
                f"{details_str}. Requires investigator review."
            )
            indicator = {
                "type": "NTFS Timestamp Discrepancy",
                "file_path": rel_path,
                "explanation": explanation,
                "diffs": field_diffs,
            }
            indicators.append(indicator)
            discrepancies.append({
                "relative_path": rel_path,
                "diffs": field_diffs,
                "si": si,
                "fn": fn,
            })

            findings.append({
                "type": "NTFS Timestamp Discrepancy",
                "severity": "HIGH",
                "evidence": f"{evidence_reference} -> {rel_path}",
                "reason": explanation,
            })

    return {
        "status": "SUCCESS",
        "evidence_reference": evidence_reference,
        "file_path": file_path,
        "evidence_type": "NTFS Forensic Image",
        "volume_info": enum_result["volume_info"],
        "records_scanned": enum_result["records_scanned"],
        "files": files,
        "discrepancies": discrepancies,
        "indicators": indicators,
        "findings": findings,
        "anomaly_detected": len(indicators) > 0,
    }
