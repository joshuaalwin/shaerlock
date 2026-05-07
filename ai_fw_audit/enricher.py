"""Pipeline glue: deterministic findings → LLM-enriched findings → evasion-linked."""

from __future__ import annotations

from .evasion import attach_evasion
from .llm.base import LLMProvider
from .schemas import EnrichedFinding, Finding


def enrich(findings: list[Finding], provider: LLMProvider) -> list[EnrichedFinding]:
    """Run LLM enrichment on each finding, then attach the deterministic
    evasion mapping. Evasion is attached unconditionally — it is reproducible
    and does not depend on the LLM, so it is present even if LLM enrichment
    falls back to its error sentinel.
    """
    out: list[EnrichedFinding] = []
    for f in findings:
        e = provider.analyze_finding(f)
        out.append(attach_evasion(e))
    return out
