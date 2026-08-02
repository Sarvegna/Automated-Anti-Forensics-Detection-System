import hashlib

def calculate_sha256(file_path):
    """
    Calculate the SHA-256 hash of a file.
    Reads the file in small chunks so even large evidence files
    (like memory dumps) don't need to be fully loaded into RAM at once.
    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()