import os
import shutil
import subprocess
from core.findings import create_finding

SUPPORTED_MEMORY_EXTENSIONS = {".mem", ".raw", ".vmem"}


def find_volatility_executable():
    """
    Locates the Volatility 3 executable on PATH, in active Python environment, or via module runner.
    Returns command prefix list e.g. ['vol'] or ['volatility3'] or None.
    """
    import sys
    venv_vol = os.path.join(os.path.dirname(sys.executable), "vol.exe")
    if os.path.isfile(venv_vol):
        return [venv_vol]
    venv_vol_noext = os.path.join(os.path.dirname(sys.executable), "vol")
    if os.path.isfile(venv_vol_noext):
        return [venv_vol_noext]

    if shutil.which("vol"):
        return ["vol"]
    if shutil.which("volatility3"):
        return ["volatility3"]
    # Check if volatility3 python module is importable
    try:
        import volatility3  # noqa: F401
        return [sys.executable, "-m", "volatility3.cli"]
    except ImportError:
        pass
    return None


def analyze_memory_image(file_path, evidence_reference=None, timeout_seconds=60):
    """
    Analyzes a memory image (.mem / .raw / .vmem) using Volatility 3.

    Returns a standardized ModuleResult dictionary:
    {
        "module_name": "Memory Analysis (Volatility 3)",
        "status": "SUCCESS" | "NOT_APPLICABLE" | "UNSUPPORTED" | "MISSING_DEPENDENCY" | "FAILED",
        "evidence_type": "Memory Image",
        "findings": [...],
        "data": {...},
        "warnings": [...],
        "errors": [...],
        "metadata": {...}
    }
    """
    if evidence_reference is None:
        evidence_reference = os.path.basename(file_path)

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    # 1. Validate file extension candidate
    if ext not in SUPPORTED_MEMORY_EXTENSIONS:
        return {
            "module_name": "Memory Analysis (Volatility 3)",
            "status": "NOT_APPLICABLE",
            "evidence_type": "Non-Memory File",
            "findings": [],
            "data": {},
            "warnings": [f"File extension '{ext}' is not a supported memory image candidate (.mem, .raw, .vmem)."],
            "errors": [],
            "metadata": {"file_path": file_path}
        }

    # 2. Check file existence and non-empty size
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return {
            "module_name": "Memory Analysis (Volatility 3)",
            "status": "FAILED",
            "evidence_type": "Invalid Memory Image",
            "findings": [],
            "data": {},
            "warnings": [],
            "errors": ["File does not exist or is 0 bytes."],
            "metadata": {"file_path": file_path}
        }

    # 3. Locate Volatility 3 executable
    vol_cmd = find_volatility_executable()
    if not vol_cmd:
        return {
            "module_name": "Memory Analysis (Volatility 3)",
            "status": "MISSING_DEPENDENCY",
            "evidence_type": "Memory Image (.mem/.raw/.vmem)",
            "findings": [],
            "data": {},
            "warnings": [
                "Volatility 3 is not installed or available on PATH. "
                "Memory analysis requires 'volatility3' CLI package."
            ],
            "errors": ["Volatility 3 executable ('vol' / 'volatility3') not found."],
            "metadata": {"file_path": file_path}
        }

    # 4. Execute Volatility 3 windows.pslist in safe subprocess
    cmd = vol_cmd + ["-f", os.path.abspath(file_path), "windows.pslist"]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        returncode = result.returncode

        if returncode != 0:
            return {
                "module_name": "Memory Analysis (Volatility 3)",
                "status": "UNSUPPORTED",
                "evidence_type": "Memory Image (Unrecognized Profile/Corrupted)",
                "findings": [],
                "data": {
                    "command": " ".join(cmd),
                    "returncode": returncode,
                    "stdout": stdout[:1000],
                    "stderr": stderr[:1000]
                },
                "warnings": ["Volatility 3 was unable to determine a valid OS profile or parse process table."],
                "errors": [f"Volatility exit code {returncode}: {stderr[:200]}"],
                "metadata": {"file_path": file_path}
            }

        # 5. Parse windows.pslist output lines
        processes = []
        lines = stdout.splitlines()
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("*") or line_str.startswith("PID"):
                continue
            parts = line_str.split()
            if len(parts) >= 3:
                try:
                    pid = int(parts[0])
                    ppid = int(parts[1])
                    image = parts[2]
                    processes.append({
                        "pid": pid,
                        "ppid": ppid,
                        "image_name": image,
                        "raw_line": line_str
                    })
                except ValueError:
                    continue

        findings = []
        if len(processes) == 0:
            # If no processes parsed, flag observation
            warnings = ["Volatility completed but extracted 0 process entries."]
        else:
            warnings = []

        return {
            "module_name": "Memory Analysis (Volatility 3)",
            "status": "SUCCESS",
            "evidence_type": "Memory Image (Windows)",
            "findings": findings,
            "data": {
                "command": " ".join(cmd),
                "total_processes": len(processes),
                "processes": processes[:50]  # Cap at 50 for summary
            },
            "warnings": warnings,
            "errors": [],
            "metadata": {
                "file_path": file_path,
                "file_size_bytes": os.path.getsize(file_path)
            }
        }

    except subprocess.TimeoutExpired:
        return {
            "module_name": "Memory Analysis (Volatility 3)",
            "status": "FAILED",
            "evidence_type": "Memory Image",
            "findings": [],
            "data": {"command": " ".join(cmd)},
            "warnings": [f"Volatility analysis timed out after {timeout_seconds} seconds."],
            "errors": [f"Subprocess timeout ({timeout_seconds}s)"],
            "metadata": {"file_path": file_path}
        }
    except Exception as e:
        return {
            "module_name": "Memory Analysis (Volatility 3)",
            "status": "FAILED",
            "evidence_type": "Memory Image",
            "findings": [],
            "data": {},
            "warnings": [],
            "errors": [f"Unexpected subprocess error: {str(e)}"],
            "metadata": {"file_path": file_path}
        }
