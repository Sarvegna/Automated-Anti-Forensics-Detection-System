import sys
import os
import subprocess

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.hidden_file_detection import check_hidden_file

# Test Case 1: Normal, visible file (our existing synthetic evidence)
normal_file = os.path.join(project_root, "evidence", "input", "sample_evidence.txt")
result = check_hidden_file(normal_file)
print("Test 1 - Normal (visible) file:")
print("  Is hidden:", result["is_hidden"])
print("  Explanation:", result["explanation"])
print()

# Test Case 2: Create a file, then set its Hidden attribute using Windows' attrib command
hidden_file = os.path.join(project_root, "evidence", "input", "hidden_test.txt")
if os.path.exists(hidden_file):
    subprocess.run(["attrib", "-H", hidden_file], check=False)
    os.remove(hidden_file)

with open(hidden_file, "w") as f:
    f.write("Synthetic file for hidden-attribute testing.")

# Use Windows' built-in attrib command to set the Hidden flag
subprocess.run(["attrib", "+H", hidden_file], check=True)

result = check_hidden_file(hidden_file)
print("Test 2 - File with Hidden attribute set:")
print("  Is hidden:", result["is_hidden"])
print("  Explanation:", result["explanation"])