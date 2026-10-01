import os
import sqlite3

# Magic Header Constants
SQLITE_HEADER = b"SQLite format 3\x00"
EVTX_HEADER = b"ElfFile\x00"
E01_HEADER_SIGS = (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00", b"EVF", b"LVF")
AFF_HEADER_SIGS = (b"AFF\x00", b"AFF")
PDF_HEADER = b"%PDF-"
ZIP_HEADER = b"PK\x03\x04"
OLE_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
JPEG_HEADER = b"\xff\xd8\xff"
PNG_HEADER = b"\x89PNG\r\n\x1a\n"
GIF_HEADERS = (b"GIF87a", b"GIF89a")
BMP_HEADER = b"BM"
DMP_HEADERS = (b"PAGE", b"DU64", b"MDMP")

# Extension candidate mapping
EXTENSION_CANDIDATE_MAP = {
    ".db": "SQLite Database Candidate",
    ".sqlite": "SQLite Database Candidate",
    ".sqlite3": "SQLite Database Candidate",
    ".db3": "SQLite Database Candidate",
    ".evtx": "Windows Event Log Candidate",
    ".e01": "E01 Forensic Image Candidate",
    ".ex01": "E01 Forensic Image Candidate",
    ".mem": "Memory Image Candidate",
    ".vmem": "Memory Image Candidate",
    ".dmp": "Memory Image Candidate",
    ".raw": "Memory / Disk Image Candidate",
    ".dd": "Disk Image Candidate",
    ".img": "Disk Image Candidate",
    ".aff": "AFF Forensic Image Candidate",
    ".aff4": "AFF Forensic Image Candidate",
    ".pdf": "PDF Document Candidate",
    ".docx": "Office OpenXML Document Candidate",
    ".xlsx": "Office OpenXML Document Candidate",
    ".pptx": "Office OpenXML Document Candidate",
    ".doc": "Office OLE Document Candidate",
    ".xls": "Office OLE Document Candidate",
    ".ppt": "Office OLE Document Candidate",
    ".jpg": "JPEG Image Candidate",
    ".jpeg": "JPEG Image Candidate",
    ".png": "PNG Image Candidate",
    ".gif": "GIF Image Candidate",
    ".bmp": "BMP Image Candidate",
}

GENERAL_ANALYSIS_LABEL = "General File"
ROUTED_GENERAL = "General Analysis only"


def _check_disk_image_signatures(header, f, file_path=None):
    """
    Checks for common disk image partition tables or filesystem boot sectors:
    MBR (0x55AA at offset 510), GPT (EFI PART at offset 512), NTFS ('NTFS    ' at offset 3),
    EXT superblock ('0x53EF' at offset 1024), ISO9660 ('CD001' at offset 32769).
    """
    if file_path:
        try:
            from core.ntfs_analysis import find_ntfs_volume
            ntfs_res = find_ntfs_volume(file_path)
            if ntfs_res.get("is_ntfs"):
                return True, "NTFS Filesystem"
        except Exception:
            pass

    if len(header) >= 512:
        # Check MBR signature at offset 510
        if header[510:512] == b"\x55\xaa":
            return True, "MBR Partition Table"
        # Check NTFS signature at offset 3
        if header[3:11] == b"NTFS    ":
            return True, "NTFS Filesystem"
        # Check FAT signature at offset 3
        if header[3:11] in (b"MSDOS5.0", b"MSWIN4.1") or (header[:1] in (b"\xeb", b"\xe9") and header[510:512] == b"\x55\xaa"):
            return True, "FAT Filesystem"

    try:
        # Check GPT signature at byte 512
        f.seek(512)
        gpt_sig = f.read(8)
        if gpt_sig == b"EFI PART":
            return True, "GPT Partition Table"

        # Check EXT superblock at byte 1024
        f.seek(1024)
        ext_sig = f.read(2)
        if ext_sig == b"\x53\xef":
            return True, "EXT Filesystem"

        # Check ISO9660 at byte 32769
        f.seek(32769)
        iso_sig = f.read(5)
        if iso_sig == b"CD001":
            return True, "ISO9660 Optical Disk Image"
    except Exception:
        pass

    return False, None



def identify_evidence(file_path):
    """
    Identifies digital evidence artifact types using content-aware detection:
    Flow: Filename/Extension -> Magic Bytes/Signature -> Schema/Content -> Artifact Type -> Confidence -> Route to Module.

    Supports read-only execution and handles extensionless or renamed artifacts.
    """
    filename = os.path.basename(file_path)
    _, extension = os.path.splitext(file_path)
    extension = extension.lower()

    candidate_label = EXTENSION_CANDIDATE_MAP.get(extension)

    # 1. Validation & Safety check
    if not os.path.isfile(file_path):
        return {
            "evidence_type": "Invalid File",
            "detected_format": "Unreadable File",
            "filename": filename,
            "extension": extension if extension else "(none)",
            "detection_method": "File System Check",
            "confidence": "LOW",
            "reason": "File does not exist or is inaccessible.",
            "routed_module": ROUTED_GENERAL,
            "supports_general_checks": False,
            "supports_specific_analysis": False
        }

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return {
            "evidence_type": "Corrupted/Empty File",
            "detected_format": "Empty (0 bytes)",
            "filename": filename,
            "extension": extension if extension else "(none)",
            "detection_method": "File Size Verification",
            "confidence": "LOW",
            "reason": "File exists but is 0 bytes (empty).",
            "routed_module": ROUTED_GENERAL,
            "supports_general_checks": True,
            "supports_specific_analysis": False
        }

    # Read initial bytes safely
    header = b""
    try:
        with open(file_path, "rb") as f:
            header = f.read(4096)
            is_disk, disk_desc = _check_disk_image_signatures(header, f, file_path=file_path)
    except Exception as e:
        return {
            "evidence_type": "Unreadable File",
            "detected_format": "Read Error",
            "filename": filename,
            "extension": extension if extension else "(none)",
            "detection_method": "Header Inspection",
            "confidence": "LOW",
            "reason": f"Failed to read file header: {str(e)}",
            "routed_module": ROUTED_GENERAL,
            "supports_general_checks": True,
            "supports_specific_analysis": False
        }

    # 2. Magic Bytes / Signature Matching
    detected_format = "Unknown Format"
    artifact_type = GENERAL_ANALYSIS_LABEL
    routed_module = ROUTED_GENERAL
    confidence = "LOW"
    detection_method = "Extension candidate only" if candidate_label else "General analysis fallthrough"
    reason = "No known file signature matched."

    # SQLite
    if len(header) >= 16 and header[:16] == SQLITE_HEADER:
        detected_format = "SQLite"
        # 3. Schema Verification for SQLite
        try:
            abs_path = os.path.abspath(file_path).replace("\\", "/")
            uri = f"file:{abs_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()

            # Check Chromium tables
            if "urls" in tables and "visits" in tables:
                artifact_type = "Browser Database (Chromium)"
                routed_module = "Browser Artifact Analysis"
                reason = f"SQLite header verified with Chromium history schema tables ({', '.join(tables[:4])})."
                if extension in (".db", ".sqlite", ".sqlite3", ".db3"):
                    confidence = "HIGH"
                    detection_method = "Extension + SQLite signature + Chromium schema"
                elif not extension or extension not in (".db", ".sqlite", ".sqlite3", ".db3"):
                    confidence = "HIGH"
                    detection_method = "SQLite signature + Chromium schema (Non-standard/Missing extension)"
            else:
                artifact_type = "SQLite Database (Non-Browser)"
                routed_module = ROUTED_GENERAL
                reason = f"SQLite header verified, but tables ({', '.join(tables[:4])}) do not match browser history schema."
                if extension in (".db", ".sqlite", ".sqlite3", ".db3"):
                    confidence = "HIGH"
                    detection_method = "Extension + SQLite signature (Non-browser schema)"
                else:
                    confidence = "HIGH"
                    detection_method = "SQLite signature (Non-browser schema)"
        except Exception as e:
            artifact_type = "Corrupted SQLite Database"
            routed_module = ROUTED_GENERAL
            confidence = "LOW"
            detection_method = "SQLite header (Database Error)"
            reason = f"SQLite magic header found, but database is corrupted or unreadable: {str(e)}"

    # Windows Event Log (.evtx)
    elif len(header) >= 8 and header[:8] == EVTX_HEADER:
        detected_format = "EVTX"
        artifact_type = "Windows Event Log"
        routed_module = "Event Log Analysis"
        reason = "EVTX magic header (ElfFile) verified."
        if extension == ".evtx":
            confidence = "HIGH"
            detection_method = "Extension + EVTX signature"
        else:
            confidence = "HIGH"
            detection_method = "EVTX signature (Non-standard/Missing extension)"

    # E01 / Expert Witness Format
    elif any(header.startswith(sig) for sig in E01_HEADER_SIGS):
        detected_format = "E01/EWF Forensic Image"
        artifact_type = "E01 Forensic Image"
        routed_module = ROUTED_GENERAL
        reason = "Expert Witness Format (E01/EWF) signature verified."
        if extension in (".e01", ".ex01"):
            confidence = "HIGH"
            detection_method = "Extension + EWF signature"
        else:
            confidence = "HIGH"
            detection_method = "EWF signature (Non-standard/Missing extension)"

    # AFF Forensic Image
    elif any(header.startswith(sig) for sig in AFF_HEADER_SIGS):
        detected_format = "AFF Forensic Image"
        artifact_type = "AFF Forensic Image"
        routed_module = ROUTED_GENERAL
        reason = "Advanced Forensic Format (AFF) signature verified."
        confidence = "HIGH" if extension in (".aff", ".aff4") else "HIGH"
        detection_method = "AFF signature"

    # Windows Memory Crash Dump (.dmp)
    elif any(header.startswith(sig) for sig in DMP_HEADERS):
        detected_format = "Windows Crash Dump"
        artifact_type = "Memory Image"
        routed_module = "Memory Analysis (Volatility 3)"
        reason = "Windows memory crash dump magic header verified."
        confidence = "HIGH"
        detection_method = "Crash dump header"

    # PDF Document
    elif header.startswith(PDF_HEADER):
        detected_format = "PDF Document"
        artifact_type = "PDF Document"
        routed_module = ROUTED_GENERAL
        reason = "PDF document magic header (%PDF-) verified."
        confidence = "HIGH" if extension == ".pdf" else "HIGH"
        detection_method = "PDF signature"

    # Office OpenXML (ZIP-based .docx, .xlsx, .pptx) or AFF4
    elif header.startswith(ZIP_HEADER):
        detected_format = "Zip Container"
        if extension in (".docx", ".xlsx", ".pptx"):
            artifact_type = "Office Document (OpenXML)"
            routed_module = ROUTED_GENERAL
            reason = "Zip container header verified for Office OpenXML document."
            confidence = "HIGH"
            detection_method = "Extension + Zip signature"
        elif extension == ".aff4":
            artifact_type = "AFF Forensic Image"
            routed_module = ROUTED_GENERAL
            reason = "AFF4 container Zip signature verified."
            confidence = "HIGH"
            detection_method = "Extension + AFF4 Zip signature"
        else:
            artifact_type = "Zip Archive"
            routed_module = ROUTED_GENERAL
            reason = "Zip container magic header (PK\\x03\\x04) verified."
            confidence = "HIGH" if extension == ".zip" else "MEDIUM"
            detection_method = "Zip signature"

    # Office OLE Compound Document (.doc, .xls, .ppt)
    elif header.startswith(OLE_HEADER):
        detected_format = "OLE Compound Document"
        artifact_type = "Office Document (OLE)"
        routed_module = ROUTED_GENERAL
        reason = "OLE Compound File binary header verified."
        confidence = "HIGH" if extension in (".doc", ".xls", ".ppt") else "MEDIUM"
        detection_method = "OLE signature"

    # JPEG Image
    elif header.startswith(JPEG_HEADER):
        detected_format = "JPEG Image"
        artifact_type = "JPEG Image"
        routed_module = ROUTED_GENERAL
        reason = "JPEG image magic header (0xFFD8FF) verified."
        confidence = "HIGH" if extension in (".jpg", ".jpeg") else "HIGH"
        detection_method = "JPEG signature"

    # PNG Image
    elif header.startswith(PNG_HEADER):
        detected_format = "PNG Image"
        artifact_type = "PNG Image"
        routed_module = ROUTED_GENERAL
        reason = "PNG image magic header (\\x89PNG) verified."
        confidence = "HIGH" if extension == ".png" else "HIGH"
        detection_method = "PNG signature"

    # GIF Image
    elif any(header.startswith(sig) for sig in GIF_HEADERS):
        detected_format = "GIF Image"
        artifact_type = "GIF Image"
        routed_module = ROUTED_GENERAL
        reason = "GIF image magic header (GIF87a/GIF89a) verified."
        confidence = "HIGH" if extension == ".gif" else "HIGH"
        detection_method = "GIF signature"

    # BMP Image
    elif header.startswith(BMP_HEADER):
        detected_format = "BMP Image"
        artifact_type = "BMP Image"
        routed_module = ROUTED_GENERAL
        reason = "BMP bitmap image magic header (BM) verified."
        confidence = "HIGH" if extension == ".bmp" else "HIGH"
        detection_method = "BMP signature"

    # Disk Image Partition / Filesystem Signatures
    elif is_disk:
        if disk_desc == "NTFS Filesystem":
            detected_format = "NTFS Disk Image"
            artifact_type = "NTFS Forensic Image"
            routed_module = "NTFS Artifact Analysis"
            reason = "Valid NTFS volume boot record and Master File Table structure verified."
            confidence = "HIGH"
            detection_method = "NTFS VBR / MFT Signature"
        else:
            detected_format = "Disk Image"
            artifact_type = "Disk Image"
            routed_module = ROUTED_GENERAL
            reason = f"Disk image structure verified ({disk_desc})."
            confidence = "HIGH" if extension in (".dd", ".img", ".raw") else "HIGH"
            detection_method = f"Disk structure signature ({disk_desc})"

    # Fallback Candidate checks & Ambiguity Resolution (.raw, .mem, .img, etc.)
    else:
        if extension in (".mem", ".vmem", ".dmp"):
            detected_format = "Raw Memory Capture"
            artifact_type = "Memory Image"
            routed_module = "Memory Analysis (Volatility 3)"
            confidence = "MEDIUM"
            detection_method = "Extension candidate (Memory dump)"
            reason = "Extension indicates memory capture image candidate."
        elif extension == ".raw":
            # Disambiguation: .raw without disk partition signature default candidate
            detected_format = "Raw Image (Memory / Disk)"
            artifact_type = "Memory Image"
            routed_module = "Memory Analysis (Volatility 3)"
            confidence = "MEDIUM"
            detection_method = "Extension candidate (.raw ambiguity rule)"
            reason = ".raw candidate without explicit disk partition table; candidate for memory analysis."
        elif extension == ".img":
            detected_format = "Raw Disk Image"
            artifact_type = "Disk Image"
            routed_module = ROUTED_GENERAL
            confidence = "MEDIUM"
            detection_method = "Extension candidate (.img disk image candidate)"
            reason = ".img extension candidate for disk image."
        elif extension in (".e01", ".ex01"):
            detected_format = "E01 Image"
            artifact_type = "E01 Forensic Image"
            routed_module = ROUTED_GENERAL
            confidence = "MEDIUM"
            detection_method = "Extension candidate (E01)"
            reason = "E01 extension candidate for forensic disk image."
        elif candidate_label:
            # Extension is known candidate, but signature was missing or unverified
            if extension in (".db", ".sqlite", ".sqlite3", ".db3"):
                artifact_type = "SQLite Database Candidate"
                confidence = "LOW"
                detection_method = "Extension only (Missing SQLite header)"
                reason = f"File has extension '{extension}', but lacks valid SQLite magic header."
            elif extension == ".evtx":
                artifact_type = "Windows Event Log Candidate"
                confidence = "LOW"
                detection_method = "Extension only (Missing EVTX header)"
                reason = "File has extension '.evtx', but lacks valid EVTX magic header."
            else:
                artifact_type = candidate_label.replace(" Candidate", "")
                confidence = "MEDIUM"
                detection_method = "Extension candidate matching"
                reason = f"Identified as candidate based on extension '{extension}'."

    # Conflict checking: extension conflicts with detected signature
    if detected_format != "Unknown Format" and candidate_label:
        # If candidate extension is .evtx but format is SQLite
        if extension == ".evtx" and detected_format == "SQLite":
            reason += f" Note: Filename extension '{extension}' conflicts with detected SQLite format."
            detection_method = "Signature over Extension Conflict"
        elif extension in (".db", ".sqlite") and detected_format == "EVTX":
            reason += f" Note: Filename extension '{extension}' conflicts with detected EVTX format."
            detection_method = "Signature over Extension Conflict"

    supports_specific = routed_module in ("Browser Artifact Analysis", "Event Log Analysis", "Memory Analysis (Volatility 3)", "NTFS Artifact Analysis")

    return {
        "evidence_type": artifact_type,
        "detected_format": detected_format,
        "filename": filename,
        "extension": extension if extension else "(none)",
        "detection_method": detection_method,
        "confidence": confidence,
        "reason": reason,
        "routed_module": routed_module,
        "supports_general_checks": True,
        "supports_specific_analysis": supports_specific
    }
