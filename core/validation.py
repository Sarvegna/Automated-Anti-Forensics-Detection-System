import os

def validate_evidence_file(file_path):
    """
    Checks whether an evidence file is valid before analysis begins.

    Checks performed:
    1. Does the file actually exist at this path?
    2. Is the file empty (0 bytes)?

    Returns a tuple: (is_valid, message)
    - is_valid: True if the file passed all checks, False otherwise
    - message: "OK" if valid, or a specific reason if not
    """
    if not os.path.exists(file_path):
        return False, "File does not exist at the given path"

    if not os.path.isfile(file_path):
        return False, "Path exists but is not a file (it may be a folder)"

    if os.path.getsize(file_path) == 0:
        return False, "File exists but is empty (0 bytes)"

    return True, "OK"