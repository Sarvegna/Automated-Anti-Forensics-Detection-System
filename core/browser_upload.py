from core.storage import add_audit_log_entry


def run_browser_upload_analysis(
    analysis_function,
    case_id,
    evidence_id,
    investigator,
    *args,
    **kwargs,
):
    try:
        return analysis_function(*args, **kwargs)
    except Exception as error:
        add_audit_log_entry(
            action="Analysis Failed",
            case_id=case_id,
            evidence_id=evidence_id,
            investigator=investigator,
            details=f"{type(error).__name__}: {error}",
        )
        raise
