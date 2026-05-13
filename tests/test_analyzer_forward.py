from pathlib import Path

from ai_fw_audit.analyzer import analyze
from ai_fw_audit.parser import parse_iptables_save
from ai_fw_audit.schemas import AnomalyClass

FIXTURE = Path(__file__).parent / "fixtures" / "flawed-forward.txt"


def _findings():
    chains = parse_iptables_save(FIXTURE.read_text())
    return analyze(chains)


def _has(findings, anomaly_class, primary_idx, secondary_idx):
    target = (anomaly_class, frozenset({primary_idx, secondary_idx}))
    actual = [(f.anomaly_class, frozenset({f.primary_idx, f.secondary_idx})) for f in findings]
    return target in actual


def test_shadowing_identical_match_different_action():
    findings = _findings()
    assert _has(findings, AnomalyClass.SHADOWING, 2, 3)


def test_generalization_narrow_then_broader():
    findings = _findings()
    assert _has(findings, AnomalyClass.GENERALIZATION, 4, 5)


def test_correlation_overlapping_port_ranges():
    findings = _findings()
    assert _has(findings, AnomalyClass.CORRELATION, 6, 7)


def test_redundancy_duplicate_udp_53():
    findings = _findings()
    assert _has(findings, AnomalyClass.REDUNDANCY, 8, 9)


def test_recall_all_four_planted_defects():
    findings = _findings()
    planted = [
        (AnomalyClass.SHADOWING, {2, 3}),
        (AnomalyClass.GENERALIZATION, {4, 5}),
        (AnomalyClass.CORRELATION, {6, 7}),
        (AnomalyClass.REDUNDANCY, {8, 9}),
    ]
    actual = {(f.anomaly_class, frozenset({f.primary_idx, f.secondary_idx})) for f in findings}
    missing = [p for p in planted if (p[0], frozenset(p[1])) not in actual]
    assert not missing, f"missing planted defects: {missing}"


def test_state_matched_rule_skipped():
    findings = _findings()
    for f in findings:
        assert f.primary_idx != 1 and f.secondary_idx != 1, \
            f"state-matched rule 1 should be skipped, but appears in {f}"


def test_exactly_four_findings():
    findings = _findings()
    assert len(findings) == 4, \
        f"expected exactly 4 findings, got {len(findings)}: " \
        f"{[(f.anomaly_class.value, f.primary_idx, f.secondary_idx) for f in findings]}"
