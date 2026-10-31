# Automated Anti-Forensics Detection System (AFDS)

A Python forensic analysis pipeline with a Streamlit web interface. It checks digital evidence for signs of anti-forensic activity (timestamp tampering, log clearing, hidden files, known anti-forensic tool patterns) and gives each case a risk score with structured findings for an investigator to review.

> **Important:** AFDS reports *indicators that require investigator review*. A finding or a risk score is a heuristic signal. It is **not proof** that anti-forensic activity or malicious behaviour occurred.

---

## Features

- **Evidence ingestion** by browser upload or local file path, with case and evidence IDs and investigator details
- **Integrity** hashing with SHA-256 for every evidence item
- **Automatic routing** of each file to the right analysis module based on its type
- **Timestamp analysis** for created, modified and accessed time anomalies
- **Hidden-file detection**
- **Windows Event Log (EVTX) analysis** for log clearing (Event IDs 1102 and 104), audit-policy changes and logging-service shutdown
- **Browser history analysis** (Chromium-based databases) for suspicious gaps
- **NTFS image analysis** for timestamp discrepancies
- **Memory image analysis** through Volatility 3 (early stage)
- **YARA scanning** for anti-forensic tool patterns
- **Risk scoring** with explainable, per-indicator findings, each showing severity (how serious it would be) and confidence (how sure we are it is real)
- **Investigator dashboard** with history, audit log and report export (JSON, HTML)

---

## How it works

```
Evidence (upload or path)
        |
   Validation  ->  SHA-256 integrity hash
        |
   Evidence identification  ->  Analysis router
        |
   Common checks:  timestamps | hidden files | YARA
        |
   Specialised modules:  EVTX | Browser DB | NTFS | Memory
        |
   Findings  ->  Risk score
        |
   Dashboard  |  History / Audit  |  Reports
```

---

## Project structure

```
app/
  streamlit_app.py        Streamlit user interface
core/
  analysis_router.py      Runs the analysis pipeline
  validation.py           File checks
  integrity.py            SHA-256 hashing
  evidence_identifier.py  Detects evidence type
  evidence_object.py      Common data object for evidence
  timestamp_analysis.py   Timestamp rules
  hidden_file_detection.py
  eventlog_analysis.py    EVTX rules (uses evtx_reader.py)
  gap_detection.py        Shared timeline-gap utility
  browser_db_analysis.py  Chromium history analysis
  ntfs_analysis.py        NTFS image analysis
  memory_analysis.py      Memory analysis via Volatility 3
  yara_analysis.py        YARA rule matching
  risk_scoring.py         Weighted scoring
  findings.py             Builds structured findings
  reporting.py            Report generation
  storage.py              Saving analysis results
tests/                    Unit tests for the core modules
evidence/                 Sample evidence used for testing
```

---

## Detection rules and risk scoring

Each indicator adds points to a score, capped at 100.

| Indicator | Points |
|---|---|
| Future timestamp | 25 |
| Log cleared (Event ID 1102) | 25 |
| System log cleared (Event ID 104) | 25 |
| NTFS timestamp discrepancy | 25 |
| YARA match | 25 |
| Modified before created | 10 |
| Accessed before created | 5 |
| Audit policy changed (Event ID 4719) | 20 |
| Event log service shutdown (Event ID 1100) | 10 |
| Timeline gap longer than 30 minutes | 15 |
| Hidden file | 10 |
| Accessed before modified | 5 |

These weights are hand-chosen heuristics and have not yet been calibrated against labelled data. Rules that often fire on normal activity (copied files, normal shutdowns) carry low weight.

Each finding also has a **confidence** label (Low, Medium or High). For example, a cleared log is High, while a YARA match or a shutdown event is Low.

---

## Installation

Requires Python 3.11 or 3.12 (recommended) and Git.

```powershell
git clone https://github.com/sarvegnatech26/Automated-Anti-Forensics-Detection-System.git
cd Automated-Anti-Forensics-Detection-System

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Main dependencies: Streamlit, python-evtx, yara-python, volatility3.

> Do not copy or move the `.venv` folder after creating it. Create a new one in the new location instead.

---

## Running the app

```powershell
python -m streamlit run app/streamlit_app.py
```

Then open `http://localhost:8501` in your browser. In the **Investigation** view, enter the investigator name, then upload an evidence file or give a local file path.

## Running the tests

```powershell
python -m pytest
```

---

## Supported evidence

| Type | Module |
|---|---|
| Windows Event Log (`.evtx`) | EVTX analysis |
| Chrome / Edge history database | Browser analysis |
| NTFS disk image | NTFS analysis |
| Memory dump | Memory analysis (early stage) |
| Any file | Timestamp, hidden-file and YARA checks |

---

## Known limitations

- **Heuristic scoring.** The weights are not calibrated, and several rules can flag normal activity (for example, files that were simply copied, or normal shutdowns).
- **Browser upload timestamps.** A browser does not send a file's created and accessed times, so file-system timestamps are only reliable when the evidence is read from its original path.
- **YARA matches** show that a pattern is present in a file, not that a tool was run.
- **Memory analysis** is at an early stage and produces limited findings.
- **No formal validation yet.** Unit tests check the code. Detection accuracy on labelled lab scenarios has not been measured.
- Windows and NTFS focused.

---

## Roadmap

- Reduce false positives further
- Correlate findings across modules and avoid counting one event twice
- Detect tool execution (Prefetch, Amcache, `$UsnJrnl`)
- Build lab scenarios with known ground truth and measure precision and recall
- Consider machine learning only if labelled data makes it justified

---

## Author

Sarvegna, B.Tech, Kalasalingam Academy of Research and Education

## License

Add a license before publishing (for example MIT) and place it in a `LICENSE` file.
