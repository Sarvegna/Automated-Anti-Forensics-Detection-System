from core.evidence_identifier import identify_evidence
from core.timestamp_analysis import analyze_timestamps
from core.hidden_file_detection import check_hidden_file
from core.evtx_reader import read_evtx_file
from core.eventlog_analysis import analyze_event_log


def run_automated_analysis(file_path):
    """
    Automatically identifies the evidence type and runs the
    appropriate combination of analysis modules.

    Returns a dictionary with:
        - identification: result from identify_evidence()
        - timestamp_result: always runs (general check)
        - hidden_file_result: always runs (general check)
        - eventlog_result: only if evidence is a Windows Event Log
        - modules_run: list of which analysis modules actually executed
    """
    identification = identify_evidence(file_path)
    modules_run = []

    # General checks - ALWAYS run, regardless of file type
    timestamp_result = analyze_timestamps(file_path)
    modules_run.append("Timestamp Analysis")

    hidden_file_result = check_hidden_file(file_path)
    modules_run.append("Hidden File Check")

    # Specific analysis - only runs if the identified type supports it
    eventlog_result = None

    if identification["evidence_type"] == "Windows Event Log":
        events = read_evtx_file(file_path)
        eventlog_result = analyze_event_log(events)
        modules_run.append("Event Log Analysis")

    return {
        "identification": identification,
        "timestamp_result": timestamp_result,
        "hidden_file_result": hidden_file_result,
        "eventlog_result": eventlog_result,
        "modules_run": modules_run
    }