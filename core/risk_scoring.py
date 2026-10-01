INDICATOR_WEIGHTS = {
    "Modified Before Created": 20,
    "Accessed Before Created": 20,
    "Future Timestamp": 25,
    "Accessed Before Modified": 10,
    "Log Cleared": 25,
    "Audit Policy Changed": 20,
    "Event Log Service Shutdown": 20,
    "Timeline Gap": 15,
    "Hidden File": 10,
    "NTFS Timestamp Discrepancy": 25,
    # YARA cross-artifact matches: all defined rules carry severity = HIGH.
    # Each distinct matched rule contributes its own weight once.
    "YARA Match": 25,
}

MAX_SCORE = 100


def _yara_weight_for_rule(rule_name):
    """
    Returns the risk point weight for a specific matched YARA rule.

    Looks up the exact rule name first (allowing future per-rule overrides),
    then falls back to the generic "YARA Match" weight.  This keeps all weight
    configuration inside INDICATOR_WEIGHTS and avoids hard-coded constants in
    scoring logic.
    """
    specific_key = f"YARA Match ({rule_name})"
    if specific_key in INDICATOR_WEIGHTS:
        return INDICATOR_WEIGHTS[specific_key]
    return INDICATOR_WEIGHTS.get("YARA Match", 25)


def _score_indicator_group(indicators, module_suffix):
    """
    Groups a list of indicator dicts by distinct ``type`` value, looks up the
    configured weight for each type, and returns a tuple:

        (total_points, contributing_entries)

    where ``contributing_entries`` is a list of dicts in the same format as
    ``calculate_risk_score``'s ``contributing_indicators`` list.

    Parameters
    ----------
    indicators : list[dict]
        Raw indicator dicts, each expected to have at least a ``"type"`` key
        and an ``"explanation"`` key.
    module_suffix : str
        Label appended to each contributing indicator's ``"type"`` field,
        e.g. ``"(Timestamp)"`` or ``"(Event Log)"``.

    Notes
    -----
    - Unknown indicator types receive 0 points (no score inflation).
    - Repeated occurrences of the same type are grouped; only the first
      occurrence's explanation is used, with an occurrence count appended
      when more than one occurrence exists.
    - Original indicator ordering within each group is preserved.
    """
    distinct_types = {}
    for ind in indicators:
        itype = ind.get("type")
        if itype not in distinct_types:
            distinct_types[itype] = []
        distinct_types[itype].append(ind)

    total_points = 0
    entries = []
    for itype, occ_list in distinct_types.items():
        points = INDICATOR_WEIGHTS.get(itype, 0)
        total_points += points
        exp = occ_list[0].get("explanation", "")
        if len(occ_list) > 1:
            exp = f"{exp} ({len(occ_list)} occurrences detected)"
        entries.append({
            "type": f"{itype} {module_suffix}",
            "points": points,
            "base_weight": points,
            "occurrences": len(occ_list),
            "explanation": exp
        })
    return total_points, entries


def calculate_risk_score(
    timestamp_result=None,
    eventlog_result=None,
    browser_result=None,
    hidden_file_result=None,
    ntfs_result=None,
    yara_result=None,
):
    """
    Combines findings from timestamp, event log, browser, hidden file,
    NTFS image, and YARA cross-artifact analysis into a single explainable
    risk score.

    Distinct-Indicator Scoring:
      Repeated occurrences of the same indicator category contribute that
      indicator's base weight once to the overall risk score, while preserving
      all occurrence records for investigator review.

    YARA Scoring:
      Each *distinct matched rule* contributes its weight once.  Multiple
      hits of the same rule in a single scan are grouped and counted as
      occurrences, not multiplied.

    Missing / Failed Modules:
      A module result whose status is "FAILED" or "MISSING_DEPENDENCY" is
      flagged as an analysis gap in contributing_indicators with 0 points.
      This ensures the result record communicates the gap to downstream
      consumers (reports, UI) without inflating the score.

    Score Boundary:
      0 <= score <= 100

    Severity Thresholds (documented in Help page):
      LOW    : 0  – 29
      MEDIUM : 30 – 59
      HIGH   : 60 – 100
    """
    contributing_indicators = []
    total_score = 0

    # 1. Timestamp Analysis Indicators
    if timestamp_result and timestamp_result.get("anomaly_detected"):
        pts, entries = _score_indicator_group(
            timestamp_result.get("indicators", []), "(Timestamp)"
        )
        total_score += pts
        contributing_indicators.extend(entries)

    # 2. Event Log Analysis Indicators
    if eventlog_result and eventlog_result.get("anomaly_detected"):
        pts, entries = _score_indicator_group(
            eventlog_result.get("indicators", []), "(Event Log)"
        )
        total_score += pts
        contributing_indicators.extend(entries)

    # 3. Browser Artifact Analysis Indicators
    if browser_result and browser_result.get("anomaly_detected"):
        pts, entries = _score_indicator_group(
            browser_result.get("indicators", []), "(Browser)"
        )
        total_score += pts
        contributing_indicators.extend(entries)

    # 4. Hidden File Check Indicator
    if hidden_file_result and hidden_file_result.get("anomaly_detected"):
        points = INDICATOR_WEIGHTS.get("Hidden File", 0)
        total_score += points
        contributing_indicators.append({
            "type": "Hidden File",
            "points": points,
            "base_weight": points,
            "occurrences": 1,
            "explanation": hidden_file_result.get("explanation")
        })

    # 5. NTFS Artifact Analysis Indicators
    if ntfs_result and ntfs_result.get("anomaly_detected"):
        pts, entries = _score_indicator_group(
            ntfs_result.get("indicators", []), "(NTFS)"
        )
        total_score += pts
        contributing_indicators.extend(entries)

    # 6. YARA Cross-Artifact Analysis
    #
    # Only SUCCESS results with actual findings contribute to the score.
    # MISSING_DEPENDENCY and FAILED are flagged as analysis gaps (0 pts) so
    # that the gap is visible in reports without inflating the score.
    if yara_result is not None:
        yara_status = yara_result.get("status", "")

        if yara_status in ("MISSING_DEPENDENCY", "FAILED"):
            # Record the analysis gap — do not contribute points
            gap_reason = (
                yara_result.get("errors", ["YARA analysis could not be completed."])[0]
                if yara_result.get("errors")
                else "YARA analysis could not be completed."
            )
            contributing_indicators.append({
                "type": "YARA Analysis (Gap — Module Unavailable)",
                "points": 0,
                "base_weight": 0,
                "occurrences": 0,
                "explanation": (
                    f"YARA cross-artifact scanning could not be completed "
                    f"(status: {yara_status}). {gap_reason} "
                    "This is an analysis gap — YARA findings are unavailable "
                    "and should be noted in the investigation record."
                )
            })

        elif yara_status == "SUCCESS":
            findings = yara_result.get("findings", [])

            # Group by distinct matched rule name
            distinct_rules = {}
            for finding in findings:
                # finding_type is e.g. "YARA Match (AntiForensic_SDelete_Signature)"
                ftype = finding.get("type", "YARA Match")
                if ftype not in distinct_rules:
                    distinct_rules[ftype] = []
                distinct_rules[ftype].append(finding)

            for rule_type, occ_list in distinct_rules.items():
                # Extract the rule name from the finding type string
                # e.g. "YARA Match (AntiForensic_SDelete_Signature)" → rule name
                rule_name = rule_type
                if rule_type.startswith("YARA Match (") and rule_type.endswith(")"):
                    rule_name = rule_type[len("YARA Match ("):-1]

                points = _yara_weight_for_rule(rule_name)
                total_score += points
                exp = occ_list[0].get("reason", "")
                if len(occ_list) > 1:
                    exp = f"{exp} ({len(occ_list)} occurrences detected)"
                contributing_indicators.append({
                    "type": f"{rule_type} (YARA)",
                    "points": points,
                    "base_weight": points,
                    "occurrences": len(occ_list),
                    "explanation": exp
                })

    # Hard bounding: 0 <= score <= 100
    bounded_score = max(0, min(total_score, MAX_SCORE))

    # Severity thresholds — must match Help page documentation:
    #   LOW: 0–29 | MEDIUM: 30–59 | HIGH: 60–100
    if bounded_score >= 60:
        risk_level = "HIGH"
    elif bounded_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": bounded_score,
        "risk_level": risk_level,
        "contributing_indicators": contributing_indicators
    }