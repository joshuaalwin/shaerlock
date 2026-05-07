from pathlib import Path

from ai_fw_audit.parser import parse_iptables_save
from ai_fw_audit.schemas import PortRange

FIXTURE = Path(__file__).parent / "fixtures" / "flawed-ruleset.txt"


def _load() -> dict:
    return parse_iptables_save(FIXTURE.read_text())


def test_parses_input_chain_with_correct_rule_count():
    chains = _load()
    assert "INPUT" in chains
    assert len(chains["INPUT"]) == 12  # only -A INPUT lines


def test_chain_indexing_is_one_based_and_per_chain():
    chains = _load()
    assert [r.chain_idx for r in chains["INPUT"]] == list(range(1, 13))


def test_protocol_and_dport_extraction():
    chains = _load()
    r3 = chains["INPUT"][2]  # `-A INPUT -p tcp --dport 22 -j ACCEPT`
    assert r3.protocol == "tcp"
    assert r3.dport.equals(PortRange(low=22, high=22))
    assert r3.action == "ACCEPT"


def test_port_range_parsing():
    chains = _load()
    r7 = chains["INPUT"][6]  # `-A INPUT -p tcp --dport 80:90 -j ACCEPT`
    assert r7.dport.equals(PortRange(low=80, high=90))


def test_state_match_flagged():
    chains = _load()
    r2 = chains["INPUT"][1]  # state ESTABLISHED,RELATED ACCEPT
    assert r2.has_state_match is True
    assert r2.is_skipped_from_pairwise() is True


def test_iface_extraction():
    chains = _load()
    r1 = chains["INPUT"][0]  # -i lo
    assert r1.in_iface == "lo"


def test_src_cidr_extraction():
    chains = _load()
    r5 = chains["INPUT"][4]  # -s 10.0.0.0/8 ACCEPT
    assert r5.src_cidr == "10.0.0.0/8"
    assert r5.action == "ACCEPT"


def test_clean_ruleset_parses():
    clean = Path(__file__).parent / "fixtures" / "clean-ruleset.txt"
    chains = parse_iptables_save(clean.read_text())
    assert "INPUT" in chains
    assert len(chains["INPUT"]) == 6
