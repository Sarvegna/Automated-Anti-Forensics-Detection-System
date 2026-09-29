# test_risk_scoring.py
# Focused pytest tests for risk-scoring pipeline including YARA integration.
#
# Covers:
#   1. YARA match integration - findings reach the score
#   2. No YARA matches - score unaffected
#   3. Missing YARA dependency - flagged as gap (0 pts)
#   4. YARA FAILED status - flagged as gap (0 pts)
#   5. Risk score arithmetic
#   6. Severity thresholds (LOW/MEDIUM/HIGH boundaries)
#   7. Duplicate finding types - counted once, occurrences preserved
#   8. Multiple distinct occurrences - count preserved
#   9. Multiple distinct YARA rules - each scored once
#   9b. Duplicate YARA rule - counted once, occurrences preserved
#  10. Clean evidence - all None -> score 0
#  11. Score hard-bounded at 100

import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import pytest
from core.risk_scoring import calculate_risk_score, INDICATOR_WEIGHTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _yara_success(matched_rules):
    """Return a SUCCESS yara_result with the given list of rule names matched."""
    from core.findings import create_finding
    findings = []
    for rule_name in matched_rules:
        findings.append(create_finding(
            finding_type="YARA Match ({})".format(rule_name),
            severity="HIGH",
            evidence_reference="test_file.bin",
            reason="YARA rule {} matched.".format(rule_name),
            source="YARA Analysis",
        ))
    return {
        "module_name": "YARA Analysis",
        "status": "SUCCESS",
        "evidence_type": "Cross-Artifact",
        "findings": findings,
        "data": {
            "total_matches": len(matched_rules),
            "matched_rules": [
                {"rule": r, "meta": {"severity": "HIGH", "description": "Rule {}".format(r)}, "tags": []}
                for r in matched_rules
            ],
        },
        "warnings": [],
        "errors": [],
        "metadata": {},
    }


def _yara_missing_dep():
    return {
        "module_name": "YARA Analysis",
        "status": "MISSING_DEPENDENCY",
        "evidence_type": "Cross-Artifact",
        "findings": [],
        "data": {},
        "warnings": ["yara-python is not installed."],
        "errors": ["ModuleNotFoundError: No module named yara"],
        "metadata": {},
    }


def _yara_failed():
    return {
        "module_name": "YARA Analysis",
        "status": "FAILED",
        "evidence_type": "Cross-Artifact",
        "findings": [],
        "data": {},
        "warnings": [],
        "errors": ["YARA rules file not found at path: /nonexistent/rules.yar"],
        "metadata": {},
    }


def _yara_clean():
    """SUCCESS result with zero matches."""
    return {
        "module_name": "YARA Analysis",
        "status": "SUCCESS",
        "evidence_type": "Cross-Artifact",
        "findings": [],
        "data": {"total_matches": 0, "matched_rules": []},
        "warnings": [],
        "errors": [],
        "metadata": {},
    }


def _eventlog(*types):
    """Synthetic eventlog_result with one indicator per type."""
    return {
        "anomaly_detected": True,
        "indicators": [{"type": t, "explanation": "ex {}".format(t)} for t in types],
    }


def _timestamp(*types):
    """Synthetic timestamp_result with one indicator per type."""
    return {
        "anomaly_detected": True,
        "indicators": [{"type": t, "explanation": "ex {}".format(t)} for t in types],
    }


# ---------------------------------------------------------------------------
# Test 1: YARA match integration
# ---------------------------------------------------------------------------

def test_yara_match_contributes_to_score():
    result = calculate_risk_score(yara_result=_yara_success(["AntiForensic_SDelete_Signature"]))
    expected = INDICATOR_WEIGHTS.get("YARA Match", 25)
    assert result["score"] == expected, "Expected score {}, got {}".format(expected, result["score"])
    assert any("YARA" in ci["type"] for ci in result["contributing_indicators"])


# ---------------------------------------------------------------------------
# Test 2: No YARA matches
# ---------------------------------------------------------------------------

def test_yara_no_matches_zero_contribution():
    result = calculate_risk_score(yara_result=_yara_clean())
    assert result["score"] == 0
    assert result["risk_level"] == "LOW"
    assert not any("YARA" in ci["type"] for ci in result["contributing_indicators"])


# ---------------------------------------------------------------------------
# Test 3: Missing YARA dependency
# ---------------------------------------------------------------------------

def test_yara_missing_dependency_is_gap():
    result = calculate_risk_score(yara_result=_yara_missing_dep())
    assert result["score"] == 0
    gaps = [ci for ci in result["contributing_indicators"] if "Gap" in ci["type"] and ci["points"] == 0]
    assert len(gaps) == 1, "Expected 1 gap indicator, got {}".format(len(gaps))
    assert "MISSING_DEPENDENCY" in gaps[0]["explanation"]


# ---------------------------------------------------------------------------
# Test 4: YARA FAILED
# ---------------------------------------------------------------------------

def test_yara_failed_is_gap():
    result = calculate_risk_score(yara_result=_yara_failed())
    assert result["score"] == 0
    gaps = [ci for ci in result["contributing_indicators"] if "Gap" in ci["type"] and ci["points"] == 0]
    assert len(gaps) == 1, "Expected 1 gap indicator, got {}".format(len(gaps))
    assert "FAILED" in gaps[0]["explanation"]


# ---------------------------------------------------------------------------
# Test 5: Risk score arithmetic
# ---------------------------------------------------------------------------

def test_risk_score_arithmetic():
    result = calculate_risk_score(eventlog_result=_eventlog("Log Cleared", "Timeline Gap"))
    expected = INDICATOR_WEIGHTS["Log Cleared"] + INDICATOR_WEIGHTS["Timeline Gap"]
    assert result["score"] == expected


# ---------------------------------------------------------------------------
# Test 6: Severity thresholds
# ---------------------------------------------------------------------------

def test_severity_low():
    # Hidden File = 10 pts -> LOW (0-29)
    result = calculate_risk_score(hidden_file_result={"anomaly_detected": True, "explanation": "h"})
    assert result["score"] == 10
    assert result["risk_level"] == "LOW"


def test_severity_medium():
    # Log Cleared(25) + Timeline Gap(15) = 40 -> MEDIUM (30-59)
    result = calculate_risk_score(eventlog_result=_eventlog("Log Cleared", "Timeline Gap"))
    assert result["score"] == 40
    assert result["risk_level"] == "MEDIUM"


def test_severity_high():
    # Future Timestamp(25) + Log Cleared(25) + NTFS Discrepancy(25) = 75 -> HIGH (>=60)
    result = calculate_risk_score(
        timestamp_result=_timestamp("Future Timestamp"),
        eventlog_result=_eventlog("Log Cleared"),
        ntfs_result={
            "anomaly_detected": True,
            "indicators": [{"type": "NTFS Timestamp Discrepancy", "explanation": "m"}]
        }
    )
    assert result["score"] == 75
    assert result["risk_level"] == "HIGH"


def test_severity_medium_boundary_below_60():
    # Log Cleared(25) + Audit Policy Changed(20) + Hidden File(10) = 55 -> MEDIUM
    result = calculate_risk_score(
        eventlog_result=_eventlog("Log Cleared", "Audit Policy Changed"),
        hidden_file_result={"anomaly_detected": True, "explanation": "h"}
    )
    assert result["score"] == 55
    assert result["risk_level"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Test 7: Duplicate finding type - counted once, occurrences preserved
# ---------------------------------------------------------------------------

def test_duplicate_indicator_type_counted_once():
    eventlog = {
        "anomaly_detected": True,
        "indicators": [
            {"type": "Log Cleared", "explanation": "first"},
            {"type": "Log Cleared", "explanation": "second"},
        ]
    }
    result = calculate_risk_score(eventlog_result=eventlog)
    assert result["score"] == INDICATOR_WEIGHTS["Log Cleared"]
    lc = [ci for ci in result["contributing_indicators"] if "Log Cleared" in ci["type"]]
    assert len(lc) == 1
    assert lc[0]["occurrences"] == 2


# ---------------------------------------------------------------------------
# Test 8: Multiple distinct occurrences preserve count
# ---------------------------------------------------------------------------

def test_multiple_occurrences_preserves_count():
    eventlog = {
        "anomaly_detected": True,
        "indicators": [
            {"type": "Timeline Gap", "explanation": "g{}".format(i)}
            for i in range(3)
        ]
    }
    result = calculate_risk_score(eventlog_result=eventlog)
    assert result["score"] == INDICATOR_WEIGHTS["Timeline Gap"]
    gc = next(ci for ci in result["contributing_indicators"] if "Timeline Gap" in ci["type"])
    assert gc["occurrences"] == 3


# ---------------------------------------------------------------------------
# Test 9a: Multiple distinct YARA rules - each scored once
# ---------------------------------------------------------------------------

def test_multiple_distinct_yara_rules():
    rules = ["AntiForensic_SDelete_Signature", "AntiForensic_LogCleaner_Reference"]
    result = calculate_risk_score(yara_result=_yara_success(rules))
    w = INDICATOR_WEIGHTS.get("YARA Match", 25)
    assert result["score"] == min(w * len(rules), 100)
    yci = [ci for ci in result["contributing_indicators"] if "YARA" in ci["type"]]
    assert len(yci) == len(rules)


# ---------------------------------------------------------------------------
# Test 9b: Duplicate YARA rule - counted once, occurrences=2
# ---------------------------------------------------------------------------

def test_duplicate_yara_rule_counted_once():
    from core.findings import create_finding
    rule = "AntiForensic_SDelete_Signature"
    findings = [
        create_finding(
            finding_type="YARA Match ({})".format(rule),
            severity="HIGH",
            evidence_reference="f",
            reason="h{}".format(i),
            source="YARA Analysis",
        )
        for i in range(2)
    ]
    yara = {
        "module_name": "YARA Analysis",
        "status": "SUCCESS",
        "evidence_type": "Cross-Artifact",
        "findings": findings,
        "data": {
            "total_matches": 2,
            "matched_rules": [
                {"rule": rule, "meta": {"severity": "HIGH"}, "tags": []},
                {"rule": rule, "meta": {"severity": "HIGH"}, "tags": []},
            ],
        },
        "warnings": [],
        "errors": [],
        "metadata": {},
    }
    result = calculate_risk_score(yara_result=yara)
    assert result["score"] == INDICATOR_WEIGHTS.get("YARA Match", 25)
    yci = [ci for ci in result["contributing_indicators"] if "YARA" in ci["type"]]
    assert len(yci) == 1
    assert yci[0]["occurrences"] == 2


# ---------------------------------------------------------------------------
# Test 10: Clean evidence - all None inputs
# ---------------------------------------------------------------------------

def test_all_none_yields_zero():
    result = calculate_risk_score()
    assert result["score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["contributing_indicators"] == []


# ---------------------------------------------------------------------------
# Test 11: Score hard-bounded at 100
# ---------------------------------------------------------------------------

def test_score_bounded_at_100():
    result = calculate_risk_score(
        timestamp_result=_timestamp("Future Timestamp", "Modified Before Created", "Accessed Before Created"),
        eventlog_result=_eventlog("Log Cleared", "Audit Policy Changed", "Event Log Service Shutdown", "Timeline Gap"),
        ntfs_result={
            "anomaly_detected": True,
            "indicators": [{"type": "NTFS Timestamp Discrepancy", "explanation": "m"}]
        },
        hidden_file_result={"anomaly_detected": True, "explanation": "h"},
        yara_result=_yara_success(["AntiForensic_SDelete_Signature", "AntiForensic_LogCleaner_Reference"]),
    )
    assert result["score"] <= 100
    assert result["risk_level"] == "HIGH"


# ---------------------------------------------------------------------------
# Test 12: NTFS unknown type — fallback must be 0, not 25
# ---------------------------------------------------------------------------

def test_ntfs_unknown_type_scores_zero():
    """An NTFS indicator whose type has no configured weight must contribute
    0 points, not the old phantom fallback of 25."""
    result = calculate_risk_score(ntfs_result={
        "anomaly_detected": True,
        "indicators": [{"type": "NTFS Unknown Future Type", "explanation": "test"}]
    })
    ci = result["contributing_indicators"]
    assert len(ci) == 1, "Expected exactly 1 contributing indicator"
    assert ci[0]["points"] == 0, (
        f"Unknown NTFS type should score 0, got {ci[0]['points']}"
    )
    assert result["score"] == 0, (
        f"Total score should be 0 for unknown NTFS type, got {result['score']}"
    )
    assert result["risk_level"] == "LOW", (
        f"Severity should be LOW, got {result['risk_level']}"
    )


# ---------------------------------------------------------------------------
# Test 13: NTFS known type — weight unchanged after fallback fix
# ---------------------------------------------------------------------------

def test_ntfs_known_type_still_scores_correctly():
    """'NTFS Timestamp Discrepancy' must still resolve to its configured weight
    (25 pts) after the fallback was changed from 25 to 0."""
    expected_pts = INDICATOR_WEIGHTS["NTFS Timestamp Discrepancy"]  # 25
    result = calculate_risk_score(ntfs_result={
        "anomaly_detected": True,
        "indicators": [{"type": "NTFS Timestamp Discrepancy", "explanation": "m"}]
    })
    ci = result["contributing_indicators"]
    assert len(ci) == 1
    assert ci[0]["points"] == expected_pts, (
        f"Expected {expected_pts} pts for 'NTFS Timestamp Discrepancy', "
        f"got {ci[0]['points']}"
    )
    assert result["score"] == expected_pts
    assert result["risk_level"] == "LOW"   # 25 < 30 threshold


# ---------------------------------------------------------------------------
# Test 14: NTFS mixed known + unknown — unknown does not pollute known score
# ---------------------------------------------------------------------------

def test_ntfs_unknown_type_does_not_pollute_known_score():
    """When both a known and an unknown NTFS type appear together, the unknown
    type must not add points; only the known type contributes."""
    known_pts = INDICATOR_WEIGHTS["NTFS Timestamp Discrepancy"]  # 25
    result = calculate_risk_score(ntfs_result={
        "anomaly_detected": True,
        "indicators": [
            {"type": "NTFS Timestamp Discrepancy", "explanation": "known"},
            {"type": "NTFS Unknown Future Type",   "explanation": "unknown"},
        ]
    })
    assert result["score"] == known_pts, (
        f"Score should be {known_pts} (known only); unknown must add 0, "
        f"got {result['score']}"
    )
    unknown_ci = [
        ci for ci in result["contributing_indicators"]
        if ci["type"] == "NTFS Unknown Future Type (NTFS)"
    ]
    assert len(unknown_ci) == 1
    assert unknown_ci[0]["points"] == 0

