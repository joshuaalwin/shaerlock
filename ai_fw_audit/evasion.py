"""Anomaly → evasion-technique mapping.

The deterministic analyzer answers *what* is broken about the policy. This
module answers *why a defender should care* by linking each anomaly class to
a concrete, named network evasion technique that exploits the gap, with a
MITRE ATT&CK reference and an academic citation.

The mapping is intentionally hardcoded (not LLM-generated) so that it is
reproducible and auditable. The LLM enrichment layer adds severity and a
plain-English explanation per finding; this layer adds the offensive
counterpart that motivates the finding.

References (IEEE-numbered; full text in docs/REFERENCES.md):
  [1] E. Al-Shaer and H. Hamed, "Discovery of Policy Anomalies in Distributed
      Firewalls," IEEE INFOCOM 2004.
  [4] T. H. Ptacek and T. N. Newsham, "Insertion, Evasion, and Denial of
      Service: Eluding Network Intrusion Detection," Secure Networks Inc.,
      1998.
  [7] MITRE ATT&CK: T1599 Network Boundary Bridging; T1572 Protocol
      Tunneling; T1562.004 Impair Defenses: Disable/Modify System Firewall.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schemas import AnomalyClass, EnrichedFinding, Finding


@dataclass(frozen=True)
class EvasionMapping:
    technique: str
    mitre_attck_id: str
    mitre_attck_name: str
    citation: str
    narrative: str


EVASION_TABLE: dict[AnomalyClass, EvasionMapping] = {
    AnomalyClass.SHADOWING: EvasionMapping(
        technique="IP fragmentation evasion of a shadowed deny rule",
        mitre_attck_id="T1599",
        mitre_attck_name="Network Boundary Bridging",
        citation="Ptacek & Newsham, 1998",
        narrative=(
            "A shadowed DROP/REJECT rule never fires, so the deny it was meant "
            "to express is silently absent from the policy. An attacker can "
            "exploit the residual permissive rule by emitting overlapping IPv4 "
            "fragments: the first fragment carries headers that match the "
            "permissive ACCEPT, and a later fragment overwrites the transport "
            "header on reassembly. Stateless filters that judged the flow on "
            "the first fragment let the reassembled (malicious) packet through. "
            "See Ptacek & Newsham, 1998 for the canonical description."
        ),
    ),
    AnomalyClass.GENERALIZATION: EvasionMapping(
        technique="Match-set widening: trigger broader allow over narrow deny",
        mitre_attck_id="T1599",
        mitre_attck_name="Network Boundary Bridging",
        citation="Al-Shaer & Hamed, 2004",
        narrative=(
            "A later rule whose match set is a strict superset of an earlier, "
            "differently-actioned rule means traffic falling outside the narrow "
            "rule's match set is handled by the broader one — and the operator "
            "may not have intended it. An attacker rewrites source ports, "
            "interfaces, or addresses so the packet falls *outside* the narrow "
            "deny but *inside* the broad allow, neutralizing the narrow rule "
            "without ever appearing on the deny path (Al-Shaer & Hamed, 2004)."
        ),
    ),
    AnomalyClass.CORRELATION: EvasionMapping(
        technique="Order-dependent rule ambiguity exploitation",
        mitre_attck_id="T1599",
        mitre_attck_name="Network Boundary Bridging",
        citation="Al-Shaer & Hamed, 2004",
        narrative=(
            "Two correlated rules with overlapping match sets and different "
            "actions resolve only by ordering — not by intent. An attacker "
            "crafts traffic that lands in the intersection of both rules so "
            "that whichever rule appears first wins. Reordering by the operator "
            "(e.g., a future merge) silently flips the policy. The pair is a "
            "latent bypass (Al-Shaer & Hamed, 2004)."
        ),
    ),
    AnomalyClass.REDUNDANCY: EvasionMapping(
        technique="Audit-gap abuse via redundant duplicate rules",
        mitre_attck_id="T1562.004",
        mitre_attck_name="Impair Defenses: Disable or Modify System Firewall",
        citation="Wool, 2004",
        narrative=(
            "A redundant rule is not directly exploitable, but it inflates the "
            "policy and creates audit fatigue: the redundant entry hides "
            "intent, makes review noisier, and increases the chance an "
            "operator deletes or edits the wrong copy. In long-lived "
            "rulesets, redundancy is the leading correlate of misconfigured "
            "production firewalls (Wool, 2004)."
        ),
    ),
}


def map_finding(finding: Finding) -> EvasionMapping:
    """Return the evasion mapping for a finding's anomaly class.

    Every AnomalyClass in the schema has an entry; KeyError here is a bug.
    """
    return EVASION_TABLE[finding.anomaly_class]


def attach_evasion(enriched: EnrichedFinding) -> EnrichedFinding:
    """Populate the evasion fields on an existing EnrichedFinding."""
    m = map_finding(enriched.finding)
    return enriched.model_copy(
        update={
            "evasion_technique": m.technique,
            "evasion_attck_id": m.mitre_attck_id,
        }
    )
