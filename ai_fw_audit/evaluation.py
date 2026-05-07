"""Evaluation harness: grade the deterministic analyzer + LLM enrichment
against an ANSWERS.md ground-truth file.

Reports recall (planted defects found), precision (extra findings), and
LLM-specific metrics: severity distribution, hallucinated rule indices,
and explanation length. Output is intentionally concrete numbers — this is
the substance that makes the writeup defensible.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from .analyzer import analyze
from .enricher import enrich
from .llm.base import get_provider
from .parser import parse_iptables_save
from .schemas import AnomalyClass, EnrichedFinding, Finding

console = Console()


_PLANTED_RE = re.compile(
    r"^\|\s*(\d+)\s*\|\s*`[^`]+`\s*\|\s*\*\*([A-Z]+)\*\*\s*\(vs idx (\d+)",
    re.MULTILINE,
)


def parse_answers(answers_path: Path) -> set[tuple[AnomalyClass, frozenset[int]]]:
    """Extract planted defects from a markdown table in ANSWERS.md.

    The expected row shape is:
        | <idx> | `<rule>` | **<CLASS>** (vs idx <other>...
    """
    text = answers_path.read_text()
    planted: set[tuple[AnomalyClass, frozenset[int]]] = set()
    for m in _PLANTED_RE.finditer(text):
        idx = int(m.group(1))
        cls_str = m.group(2)
        other = int(m.group(3))
        try:
            cls = AnomalyClass(cls_str)
        except ValueError:
            continue
        planted.add((cls, frozenset({idx, other})))
    return planted


def _findings_as_set(findings: list[Finding]) -> set[tuple[AnomalyClass, frozenset[int]]]:
    return {(f.anomaly_class, frozenset({f.primary_idx, f.secondary_idx})) for f in findings}


def grade_against_answers(
    ruleset: Path,
    answers: Path,
    provider: str = "auto",
    out: Optional[Path] = None,
) -> dict:
    chains = parse_iptables_save(ruleset.read_text())
    findings = analyze(chains)
    planted = parse_answers(answers)
    found = _findings_as_set(findings)

    tp = planted & found
    fp = found - planted
    fn = planted - found

    recall = len(tp) / len(planted) if planted else 0.0
    precision = len(tp) / len(found) if found else 0.0

    p = get_provider(provider) if provider != "none" else None
    enriched: list[EnrichedFinding] = enrich(findings, p) if p else []

    valid_indices = {r.chain_idx for rs in chains.values() for r in rs}
    hallucinations = []
    severity_counts: dict[str, int] = {}
    if enriched:
        for e in enriched:
            severity_counts[e.severity.value] = severity_counts.get(e.severity.value, 0) + 1
            for idx in (e.finding.primary_idx, e.finding.secondary_idx):
                if idx not in valid_indices:
                    hallucinations.append({"idx": idx, "class": e.finding.anomaly_class.value})

    report = {
        "ruleset": str(ruleset),
        "answers": str(answers),
        "provider": p.name if p else "none",
        "deterministic": {
            "planted": len(planted),
            "found": len(found),
            "true_positive": len(tp),
            "false_positive": len(fp),
            "false_negative": len(fn),
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "missing_planted_defects": [
                {"class": c.value, "rules": sorted(s)} for c, s in sorted(fn, key=lambda x: sorted(x[1]))
            ],
        },
        "llm": {
            "enriched_count": len(enriched),
            "severity_distribution": severity_counts,
            "hallucinated_rule_refs": hallucinations,
            "samples": [
                {
                    "class": e.finding.anomaly_class.value,
                    "rules": [e.finding.primary_idx, e.finding.secondary_idx],
                    "severity": e.severity.value,
                    "explanation": e.explanation,
                    "suggested_fix": e.suggested_fix,
                }
                for e in enriched[:5]
            ],
        },
    }

    _print_report(report)
    if out:
        out.write_text(json.dumps(report, indent=2))
        console.print(f"[dim]wrote {out}[/]")
    return report


def _print_report(report: dict):
    d = report["deterministic"]
    t = Table(title="Deterministic vs ground truth", header_style="bold")
    t.add_column("metric"); t.add_column("value", justify="right")
    for k in ("planted", "found", "true_positive", "false_positive", "false_negative", "recall", "precision"):
        t.add_row(k, str(d[k]))
    console.print(t)
    if d["missing_planted_defects"]:
        console.print(f"[red]missing planted defects:[/] {d['missing_planted_defects']}")

    llm = report["llm"]
    if llm["enriched_count"]:
        t2 = Table(title=f"LLM enrichment ({report['provider']})", header_style="bold")
        t2.add_column("metric"); t2.add_column("value", justify="right")
        t2.add_row("enriched", str(llm["enriched_count"]))
        for sev, n in sorted(llm["severity_distribution"].items()):
            t2.add_row(f"severity[{sev}]", str(n))
        t2.add_row("hallucinated_rule_refs", str(len(llm["hallucinated_rule_refs"])))
        console.print(t2)
