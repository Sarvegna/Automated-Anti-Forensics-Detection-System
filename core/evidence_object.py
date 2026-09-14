import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from core.validation import validate_evidence_file

FORENSIC_IMAGE_EXTENSIONS = {".e01", ".ex01", ".dd", ".raw", ".img", ".aff", ".aff4"}


@dataclass
class EvidenceObject:
    """
    Structured evidence abstraction representing an uploaded evidence item.

    Attributes:
        source_type: "forensic_image" or "individual_file"
        path: Absolute or relative file path to the evidence
        sha256: SHA-256 hash string of the evidence file
        hash_algorithm: Hashing algorithm name (default: "SHA-256")
        evidence_reference: Human-readable reference or original filename
        source_metadata: Additional context dictionary (e.g. web upload info)
    """
    source_type: str
    path: str
    sha256: str
    hash_algorithm: str = "SHA-256"
    evidence_reference: Optional[str] = None
    source_metadata: Optional[Dict[str, Any]] = None

    @property
    def source(self) -> str:
        """Alias for source_type matching the conceptual schema."""
        return self.source_type

    @property
    def hash(self) -> str:
        """Alias for sha256 matching the conceptual schema."""
        return self.sha256

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source": self.source_type,
            "path": self.path,
            "sha256": self.sha256,
            "hash": self.sha256,
            "hash_algorithm": self.hash_algorithm,
            "evidence_reference": self.evidence_reference or os.path.basename(self.path),
            "source_metadata": self.source_metadata or {}
        }


def identify_source_type(file_path: str) -> str:
    """
    Identifies evidence input mode based on file extension.
    Returns 'forensic_image' if extension is a known forensic image format (.E01, .dd, .raw, .img, etc.),
    otherwise returns 'individual_file'.
    """
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext in FORENSIC_IMAGE_EXTENSIONS:
        return "forensic_image"
    return "individual_file"


def create_evidence_object(
    file_path: str,
    evidence_reference: Optional[str] = None,
    source_metadata: Optional[Dict[str, Any]] = None
) -> EvidenceObject:
    """
    Validates evidence path, calculates SHA-256, identifies source type,
    and returns a tagged EvidenceObject.
    """
    from core.integrity import calculate_sha256

    is_valid, msg = validate_evidence_file(file_path)
    if not is_valid:
        raise ValueError(f"Evidence validation failed: {msg}")

    sha256_hash = calculate_sha256(file_path)
    source_type = identify_source_type(file_path)

    if evidence_reference is None:
        evidence_reference = os.path.basename(file_path)

    return EvidenceObject(
        source_type=source_type,
        path=file_path,
        sha256=sha256_hash,
        hash_algorithm="SHA-256",
        evidence_reference=evidence_reference,
        source_metadata=source_metadata
    )
