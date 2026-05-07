"""Offline evaluation-harness sanity test (no LLM)."""

from pathlib import Path

from ai_fw_audit.evaluation import grade_against_answers, parse_answers

FIXTURES = Path(__file__).parent / "fixtures"
RULESET = FIXTURES / "flawed-ruleset.txt"
ANSWERS = FIXTURES / "flawed-ruleset.ANSWERS.md"


def test_parse_answers_extracts_five_planted_defects():
    planted = parse_answers(ANSWERS)
    assert len(planted) == 5
    classes = {c.value for c, _ in planted}
    assert classes == {"REDUNDANCY", "SHADOWING", "CORRELATION", "GENERALIZATION"}


def test_grade_recall_is_perfect_with_no_llm(tmp_path):
    out = tmp_path / "report.json"
    report = grade_against_answers(RULESET, ANSWERS, provider="none", out=out)
    d = report["deterministic"]
    assert d["planted"] == 5
    assert d["true_positive"] == 5
    assert d["false_negative"] == 0
    assert d["recall"] == 1.0
    assert out.exists()
