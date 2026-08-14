import os

# Maps file extensions to the evidence type they represent.
# This is extension-based identification - a known, documented
# limitation (real forensic tools also check file signatures/magic
# bytes, since extensions can be renamed - a future enhancement).
EXTENSION_MAP = {
    ".evtx": "Windows Event Log",
    ".db": "Browser Database",
    ".sqlite": "Browser Database",
    ".mem": "Memory Image",
    ".raw": "Memory Image",
}

# File types that support general checks (timestamp, hidden file)
# regardless of their specific evidence type - these run on
# virtually any file.
GENERAL_ANALYSIS_LABEL = "General File"


def identify_evidence(file_path):
    """
    Identifies the evidence/artifact type of an uploaded file,
    based on its extension.

    Returns a dictionary with:
        - evidence_type: str, human-readable type label
        - extension: the file's extension
        - supports_general_checks: bool - True for any file (timestamp,
          hidden file checks apply)
        - supports_specific_analysis: bool - True if a dedicated
          module exists for this type (event log, browser, etc.)
    """
    _, extension = os.path.splitext(file_path)
    extension = extension.lower()

    specific_type = EXTENSION_MAP.get(extension)

    if specific_type:
        evidence_type = specific_type
        supports_specific_analysis = True
    else:
        evidence_type = GENERAL_ANALYSIS_LABEL
        supports_specific_analysis = False

    return {
        "evidence_type": evidence_type,
        "extension": extension if extension else "(none)",
        "supports_general_checks": True,  # timestamp/hidden file work on ANY file
        "supports_specific_analysis": supports_specific_analysis
    }