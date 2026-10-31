import pytest

from core.yara_analysis import analyze_with_yara


def _analyze_text(tmp_path, filename, contents):
    pytest.importorskip(
        "yara",
        reason="yara-python is not installed; YARA rule behavior cannot be tested.",
    )
    sample_path = tmp_path / filename
    sample_path.write_text(contents, encoding="utf-8")
    result = analyze_with_yara(str(sample_path))
    assert result["status"] == "SUCCESS", result
    return {match["rule"] for match in result["data"]["matched_rules"]}


def test_sdelete_matches_two_clues(tmp_path):
    matches = _analyze_text(
        tmp_path,
        "sdelete_two_clues.txt",
        "sdelete tool; Secure Delete utility",
    )
    assert matches == {"AntiForensic_SDelete_Signature"}


def test_single_rule_clue_does_not_match(tmp_path):
    matches = _analyze_text(tmp_path, "one_clue.txt", "sdelete")
    assert matches == set()


def test_ordinary_text_does_not_match(tmp_path):
    matches = _analyze_text(
        tmp_path,
        "ordinary_text.txt",
        "This is an ordinary report about a routine system check.",
    )
    assert matches == set()


def test_logcleaner_matches_two_clues(tmp_path):
    matches = _analyze_text(
        tmp_path,
        "logcleaner_two_clues.txt",
        "wevtutil cl System; Clear-EventLog",
    )
    assert matches == {"AntiForensic_LogCleaner_Reference"}


def test_timestomp_matches_two_clues(tmp_path):
    matches = _analyze_text(
        tmp_path,
        "timestomp_two_clues.txt",
        "timestomp utility; setmtime command",
    )
    assert matches == {"AntiForensic_Timestomp_Indicator"}
