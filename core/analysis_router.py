from core.evidence_identifier import identify_evidence
from core.timestamp_analysis import analyze_timestamps
from core.hidden_file_detection import check_hidden_file
from core.evtx_reader import read_evtx_file
from core.eventlog_analysis import analyze_event_log
from core.risk_scoring import calculate_risk_score
from core.findings import build_findings_from_risk_result


def run_automated_analysis(file_path, evidence_reference=None):
    """
    Automatically identifies the evidence type, runs the appropriate
    combination of analysis modules, calculates a risk score, and
    generates structured findings - the full automated pipeline.

    Parameters:
        file_path: path to the evidence file to analyze
        evidence_reference: human-readable label for this evidence
                           (defaults to the filename if not given)

    Returns a dictionary with:
        - identification, timestamp_result, hidden_file_result,
          eventlog_result: raw results from each module (as before)
        - modules_run: list of which analysis modules executed
        - risk_result: combined score, level, contributing indicators
        - findings: structured Finding records with unique IDs
    """
    if evidence_reference is None:
        evidence_reference = file_path.split("\\")[-1].split("/")[-1]

    identification = identify_evidence(file_path)
    modules_run = []

    timestamp_result = analyze_timestamps(file_path)
    modules_run.append("Timestamp Analysis")

    hidden_file_result = check_hidden_file(file_path)
    modules_run.append("Hidden File Check")

    eventlog_result = None
    if identification["evidence_type"] == "Windows Event Log":
        events = read_evtx_file(file_path)
        eventlog_result = analyze_event_log(events)
        modules_run.append("Event Log Analysis")

    # Combine everything into a risk score
    risk_result = calculate_risk_score(
        timestamp_result=timestamp_result,
        eventlog_result=eventlog_result,
        hidden_file_result=hidden_file_result
    )

    # Generate structured, traceable findings
    findings = build_findings_from_risk_result(risk_result, evidence_reference)

    return {
        "identification": identification,
        "timestamp_result": timestamp_result,
        "hidden_file_result": hidden_file_result,
        "eventlog_result": eventlog_result,
        "modules_run": modules_run,
        "risk_result": risk_result,
        "findings": findings
    }