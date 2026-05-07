"""Deterministic Al-Shaer & Hamed pairwise firewall anomaly detection.

Reference: E. Al-Shaer and H. Hamed, "Discovery of Policy Anomalies in
Distributed Firewalls," IEEE INFOCOM 2004, and the 2005 journal extension.

For two rules R_i (earlier) and R_j (later, i < j) in the same chain, with
match-sets M_i and M_j and actions A_i, A_j:

    M_j ⊆ M_i, A_i = A_j  →  REDUNDANCY  (R_j unnecessary)
    M_j ⊆ M_i, A_i ≠ A_j  →  SHADOWING   (R_j unreachable)
    M_i ⊊ M_j, A_i = A_j  →  REDUNDANCY  (R_i could be folded into R_j)
    M_i ⊊ M_j, A_i ≠ A_j  →  GENERALIZATION
    M_i ∩ M_j ≠ ∅, neither subset, A_i ≠ A_j  →  CORRELATION
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from .schemas import AnomalyClass, Finding, PortRange, Rule


# ---- match-set primitives ------------------------------------------------

def _proto_contains(a: Optional[str], b: Optional[str]) -> bool:
    """`a` is at least as broad as `b` w.r.t. protocol."""
    if a is None or a == "all":
        return True
    if b is None or b == "all":
        return False
    return a == b


def _proto_intersects(a: Optional[str], b: Optional[str]) -> bool:
    if a is None or a == "all" or b is None or b == "all":
        return True
    return a == b


def _cidr(cidr: Optional[str]):
    if cidr is None:
        return ipaddress.ip_network("0.0.0.0/0")
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return ipaddress.ip_network("0.0.0.0/0")


def _cidr_contains(a: Optional[str], b: Optional[str]) -> bool:
    return _cidr(b).subnet_of(_cidr(a))


def _cidr_intersects(a: Optional[str], b: Optional[str]) -> bool:
    return _cidr(a).overlaps(_cidr(b))


def _iface_contains(a: Optional[str], b: Optional[str]) -> bool:
    if a is None:
        return True
    return a == b


def _iface_intersects(a: Optional[str], b: Optional[str]) -> bool:
    if a is None or b is None:
        return True
    return a == b


def _port_contains(a: PortRange, b: PortRange) -> bool:
    return a.contains(b)


def _port_intersects(a: PortRange, b: PortRange) -> bool:
    return a.intersects(b)


# ---- rule-level relations ------------------------------------------------

def match_subset(a: Rule, b: Rule) -> bool:
    """True iff M_b ⊆ M_a (every packet matching b also matches a)."""
    return (
        _proto_contains(a.protocol, b.protocol)
        and _cidr_contains(a.src_cidr, b.src_cidr)
        and _cidr_contains(a.dst_cidr, b.dst_cidr)
        and _port_contains(a.sport, b.sport)
        and _port_contains(a.dport, b.dport)
        and _iface_contains(a.in_iface, b.in_iface)
        and _iface_contains(a.out_iface, b.out_iface)
    )


def match_equal(a: Rule, b: Rule) -> bool:
    return match_subset(a, b) and match_subset(b, a)


def match_intersects(a: Rule, b: Rule) -> bool:
    return (
        _proto_intersects(a.protocol, b.protocol)
        and _cidr_intersects(a.src_cidr, b.src_cidr)
        and _cidr_intersects(a.dst_cidr, b.dst_cidr)
        and _port_intersects(a.sport, b.sport)
        and _port_intersects(a.dport, b.dport)
        and _iface_intersects(a.in_iface, b.in_iface)
        and _iface_intersects(a.out_iface, b.out_iface)
    )


# ---- main detector -------------------------------------------------------

def _classify_pair(r_i: Rule, r_j: Rule) -> Optional[Finding]:
    """Classify the relation between an earlier rule r_i and later rule r_j."""
    same_action = r_i.action == r_j.action

    j_in_i = match_subset(r_i, r_j)  # M_j ⊆ M_i
    i_in_j = match_subset(r_j, r_i)  # M_i ⊆ M_j

    if j_in_i and i_in_j:
        # Identical match sets.
        if same_action:
            cls = AnomalyClass.REDUNDANCY
            expl = (
                f"rule {r_j.chain_idx} has the same match set and same action as "
                f"rule {r_i.chain_idx}; rule {r_j.chain_idx} is unreachable and unnecessary"
            )
        else:
            cls = AnomalyClass.SHADOWING
            expl = (
                f"rule {r_j.chain_idx} has the same match set as rule {r_i.chain_idx} "
                f"but a different action ({r_j.action} vs {r_i.action}); "
                f"rule {r_j.chain_idx} can never fire"
            )
        return Finding(
            anomaly_class=cls,
            primary_idx=r_i.chain_idx,
            secondary_idx=r_j.chain_idx,
            chain=r_i.chain,
            explanation=expl,
            primary_raw=r_i.raw,
            secondary_raw=r_j.raw,
        )

    if j_in_i:
        # M_j ⊊ M_i
        if same_action:
            cls = AnomalyClass.REDUNDANCY
            expl = (
                f"rule {r_j.chain_idx} matches a strict subset of rule {r_i.chain_idx} "
                f"with the same action; rule {r_j.chain_idx} is redundant"
            )
        else:
            cls = AnomalyClass.SHADOWING
            expl = (
                f"rule {r_j.chain_idx} matches a strict subset of rule {r_i.chain_idx} "
                f"but with a different action ({r_j.action} vs {r_i.action}); "
                f"rule {r_j.chain_idx} is shadowed and unreachable"
            )
        return Finding(
            anomaly_class=cls,
            primary_idx=r_i.chain_idx,
            secondary_idx=r_j.chain_idx,
            chain=r_i.chain,
            explanation=expl,
            primary_raw=r_i.raw,
            secondary_raw=r_j.raw,
        )

    if i_in_j:
        # M_i ⊊ M_j: r_i is a special case of r_j.
        if same_action:
            cls = AnomalyClass.REDUNDANCY
            expl = (
                f"rule {r_i.chain_idx} matches a strict subset of rule {r_j.chain_idx} "
                f"with the same action; rule {r_i.chain_idx} could be folded into rule {r_j.chain_idx}"
            )
        else:
            cls = AnomalyClass.GENERALIZATION
            expl = (
                f"rule {r_j.chain_idx} generalizes rule {r_i.chain_idx} "
                f"(strict superset of the match set) with a different action "
                f"({r_j.action} vs {r_i.action}); intent ambiguity, and rule {r_j.chain_idx} "
                f"covers traffic that rule {r_i.chain_idx} would have handled differently"
            )
        return Finding(
            anomaly_class=cls,
            primary_idx=r_j.chain_idx,
            secondary_idx=r_i.chain_idx,
            chain=r_i.chain,
            explanation=expl,
            primary_raw=r_j.raw,
            secondary_raw=r_i.raw,
        )

    # Neither is a subset of the other; check for genuine intersection.
    if match_intersects(r_i, r_j) and not same_action:
        return Finding(
            anomaly_class=AnomalyClass.CORRELATION,
            primary_idx=r_i.chain_idx,
            secondary_idx=r_j.chain_idx,
            chain=r_i.chain,
            explanation=(
                f"rules {r_i.chain_idx} and {r_j.chain_idx} have overlapping match sets "
                f"but neither is a subset of the other, and their actions differ "
                f"({r_i.action} vs {r_j.action}); ordering decides which fires"
            ),
            primary_raw=r_i.raw,
            secondary_raw=r_j.raw,
        )

    return None


def analyze_chain(rules: list[Rule]) -> list[Finding]:
    """Run pairwise anomaly detection on a single chain's rules."""
    findings: list[Finding] = []
    n = len(rules)
    for i in range(n):
        if rules[i].is_skipped_from_pairwise():
            continue
        for j in range(i + 1, n):
            if rules[j].is_skipped_from_pairwise():
                continue
            f = _classify_pair(rules[i], rules[j])
            if f is not None:
                findings.append(f)
    return findings


def analyze(chains: dict[str, list[Rule]]) -> list[Finding]:
    findings: list[Finding] = []
    for _, rules in chains.items():
        findings.extend(analyze_chain(rules))
    return findings


def skipped_rules(chains: dict[str, list[Rule]]) -> list[Rule]:
    """Rules excluded from pairwise analysis (stateful, negated, unhandled match)."""
    return [r for rs in chains.values() for r in rs if r.is_skipped_from_pairwise()]
