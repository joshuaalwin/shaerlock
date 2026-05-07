from pathlib import Path

from ai_fw_audit.analyzer import analyze
from ai_fw_audit.parser import parse_iptables_save
from ai_fw_audit.schemas import AnomalyClass

FIXTURE = Path(__file__).parent / "fixtures" / "flawed-ruleset.txt"
CLEAN = Path(__file__).parent / "fixtures" / "clean-ruleset.txt"


def _findings():
    chains = parse_iptables_save(FIXTURE.read_text())
    return analyze(chains)


def _has(findings, anomaly_class, primary_idx, secondary_idx):
    """Check the analyzer reports the expected pair (order-tolerant on idx)."""
    target = (anomaly_class, frozenset({primary_idx, secondary_idx}))
    actual = [(f.anomaly_class, frozenset({f.primary_idx, f.secondary_idx})) for f in findings]
    return target in actual


# --- planted defect coverage (ground truth from ANSWERS.md) ---

def test_redundancy_dport_22_duplicate():
    findings = _findings()
    assert _has(findings, AnomalyClass.REDUNDANCY, 3, 4), \
        "expected REDUNDANCY between rule 3 and rule 4 (duplicate tcp dport 22 ACCEPT)"


def test_shadowing_cidr_subnet():
    findings = _findings()
    assert _has(findings, AnomalyClass.SHADOWING, 5, 6), \
        "expected SHADOWING of rule 6 (10.1/16 DROP) by rule 5 (10/8 ACCEPT)"


def test_correlation_overlapping_port_ranges():
    findings = _findings()
    assert _has(findings, AnomalyClass.CORRELATION, 7, 8), \
        "expected CORRELATION between rule 7 (tcp dport 80:90 ACCEPT) and rule 8 (85:95 DROP)"


def test_generalization_specific_then_broader():
    findings = _findings()
    assert _has(findings, AnomalyClass.GENERALIZATION, 9, 10), \
        "expected GENERALIZATION of rule 9 (tcp dport 8080 DROP) by rule 10 (tcp dport 8000:9000 ACCEPT)"


def test_shadowing_identical_match_different_action():
    findings = _findings()
    assert _has(findings, AnomalyClass.SHADOWING, 11, 12), \
        "expected SHADOWING of rule 12 (udp dport 53 DROP) by rule 11 (udp dport 53 ACCEPT)"


def test_recall_at_least_5_planted_defects():
    findings = _findings()
    planted = [
        (AnomalyClass.REDUNDANCY, {3, 4}),
        (AnomalyClass.SHADOWING, {5, 6}),
        (AnomalyClass.CORRELATION, {7, 8}),
        (AnomalyClass.GENERALIZATION, {9, 10}),
        (AnomalyClass.SHADOWING, {11, 12}),
    ]
    actual = {(f.anomaly_class, frozenset({f.primary_idx, f.secondary_idx})) for f in findings}
    missing = [p for p in planted if (p[0], frozenset(p[1])) not in actual]
    assert not missing, f"missing planted defects: {missing}"


def test_state_matched_rule_skipped_from_pairwise():
    """Rule 2 (state ESTABLISHED,RELATED) must not appear in any finding pair."""
    findings = _findings()
    for f in findings:
        assert f.primary_idx != 2 and f.secondary_idx != 2, \
            f"state-matched rule 2 should be skipped, but appears in {f}"


def test_clean_ruleset_yields_no_findings():
    chains = parse_iptables_save(CLEAN.read_text())
    findings = analyze(chains)
    assert findings == [], f"unexpected findings on clean ruleset: {findings}"
