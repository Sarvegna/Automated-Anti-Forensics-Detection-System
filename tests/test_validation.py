import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.validation import validate_evidence_file

# Test Case 1: Valid file (our synthetic evidence from Phase 6)
valid_file = os.path.join(project_root, "evidence", "input", "sample_evidence.txt")
result = validate_evidence_file(valid_file)
print("Test 1 - Valid file:", result)

# Test Case 2: File that doesn't exist
missing_file = os.path.join(project_root, "evidence", "input", "does_not_exist.txt")
result = validate_evidence_file(missing_file)
print("Test 2 - Missing file:", result)

# Test Case 3: Empty file
empty_file = os.path.join(project_root, "evidence", "input", "empty_evidence.txt")
result = validate_evidence_file(empty_file)
print("Test 3 - Empty file:", result)