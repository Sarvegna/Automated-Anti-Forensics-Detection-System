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
}

MAX_SCORE = 100


def calculate_risk_score(timestamp_result=None, eventlog_result=None, browser_result=None, hidden_file_result=None, ntfs_result=None):
    """
    Combines findings from timestamp, event log, browser, hidden file,
    and NTFS image analysis into a single explainable risk score.

    Distinct-Indicator Scoring:
      Repeated occurrences of the same indicator category contribute that
      indicator's base weight once to the overall risk score, while preserving
      all occurrence records for investigator review.

    Score Boundary:
      0 <= score <= 100
    """
    contributing_indicators = []
    total_score = 0

    # 1. Timestamp Analysis Indicators
    if timestamp_result and timestamp_result.get("anomaly_detected"):
        indicators = timestamp_result.get("indicators", [])
        # Group by distinct indicator type
        distinct_types = {}
        for ind in indicators:
            itype = ind.get("type")
            if itype not in distinct_types:
                distinct_types[itype] = []
            distinct_types[itype].append(ind)

        for itype, occ_list in distinct_types.items():
            points = INDICATOR_WEIGHTS.get(itype, 0)
            total_score += points
            exp = occ_list[0].get("explanation", "")
            if len(occ_list) > 1:
                exp = f"{exp} ({len(occ_list)} occurrences detected)"
            contributing_indicators.append({
                "type": f"{itype} (Timestamp)",
                "points": points,
                "base_weight": points,
                "occurrences": len(occ_list),
                "explanation": exp
            })

    # 2. Event Log Analysis Indicators
    if eventlog_result and eventlog_result.get("anomaly_detected"):
        indicators = eventlog_result.get("indicators", [])
        distinct_types = {}
        for ind in indicators:
            itype = ind.get("type")
            if itype not in distinct_types:
                distinct_types[itype] = []
            distinct_types[itype].append(ind)

        for itype, occ_list in distinct_types.items():
            points = INDICATOR_WEIGHTS.get(itype, 0)
            total_score += points
            exp = occ_list[0].get("explanation", "")
            if len(occ_list) > 1:
                exp = f"{exp} ({len(occ_list)} occurrences detected)"
            contributing_indicators.append({
                "type": f"{itype} (Event Log)",
                "points": points,
                "base_weight": points,
                "occurrences": len(occ_list),
                "explanation": exp
            })

    # 3. Browser Artifact Analysis Indicators
    if browser_result and browser_result.get("anomaly_detected"):
        indicators = browser_result.get("indicators", [])
        distinct_types = {}
        for ind in indicators:
            itype = ind.get("type")
            if itype not in distinct_types:
                distinct_types[itype] = []
            distinct_types[itype].append(ind)

        for itype, occ_list in distinct_types.items():
            points = INDICATOR_WEIGHTS.get(itype, 0)
            total_score += points
            exp = occ_list[0].get("explanation", "")
            if len(occ_list) > 1:
                exp = f"{exp} ({len(occ_list)} occurrences detected)"
            contributing_indicators.append({
                "type": f"{itype} (Browser)",
                "points": points,
                "base_weight": points,
                "occurrences": len(occ_list),
                "explanation": exp
            })

    # 4. Hidden File Check Indicator
    if hidden_file_result and hidden_file_result.get("anomaly_detected"):
        points = INDICATOR_WEIGHTS.get("Hidden File", 10)
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
        indicators = ntfs_result.get("indicators", [])
        distinct_types = {}
        for ind in indicators:
            itype = ind.get("type")
            if itype not in distinct_types:
                distinct_types[itype] = []
            distinct_types[itype].append(ind)

        for itype, occ_list in distinct_types.items():
            points = INDICATOR_WEIGHTS.get(itype, 25)
            total_score += points
            exp = occ_list[0].get("explanation", "")
            if len(occ_list) > 1:
                exp = f"{exp} ({len(occ_list)} occurrences detected)"
            contributing_indicators.append({
                "type": f"{itype} (NTFS)",
                "points": points,
                "base_weight": points,
                "occurrences": len(occ_list),
                "explanation": exp
            })

    # Hard bounding: 0 <= score <= 100
    bounded_score = max(0, min(total_score, MAX_SCORE))

    if bounded_score >= 20:
        risk_level = "HIGH"
    elif bounded_score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": bounded_score,
        "risk_level": risk_level,
        "contributing_indicators": contributing_indicators
    }