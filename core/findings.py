import uuid


def create_finding(finding_type, severity, evidence_reference, reason, source, points=0):
    """
    Creates a structured, traceable finding record.
    """
    finding_id = f"AF-{str(uuid.uuid4())[:8].upper()}"

    return {
        "finding_id": finding_id,
        "type": finding_type,
        "severity": severity,
        "points": points,
        "evidence": evidence_reference,
        "reason": reason,
        "source": source
    }


def severity_from_points(points):
    """
    Maps a point value to a severity label.
    """
    if points >= 20:
        return "HIGH"
    elif points >= 15:
        return "MEDIUM"
    else:
        return "LOW"


def build_findings_from_risk_result(risk_result, evidence_reference):
    """
    Converts risk_scoring's contributing_indicators list into
    proper structured Finding records with unique IDs.
    """
    findings = []

    for indicator in risk_result.get("contributing_indicators", []):
        points = indicator.get("points", 0)
        finding = create_finding(
            finding_type=indicator["type"],
            severity=severity_from_points(points),
            evidence_reference=evidence_reference,
            reason=indicator["explanation"],
            source=indicator["type"],
            points=points
        )
        findings.append(finding)

    return findings