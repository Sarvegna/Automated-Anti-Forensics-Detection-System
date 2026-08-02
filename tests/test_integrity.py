import sys
import os

# Get the absolute path to the project root (one folder above "tests")
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.integrity import calculate_sha256

# Build an absolute path to our evidence file too
file_path = os.path.join(project_root, "evidence", "input", "sample_evidence.txt")

hash_result = calculate_sha256(file_path)

print("File:", file_path)
print("SHA-256:", hash_result)