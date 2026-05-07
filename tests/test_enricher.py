"""Offline enrichment test using a mock LLM provider.

This test does NOT require an API key or local model. It verifies that the
enrichment pipeline correctly wires findings through a provider and validates
the structured output schema.
"""

from pathlib import Path

from ai_fw_audit.analyzer import analyze
from ai_fw_audit.enricher import enrich
from ai_fw_audit.llm.base import LLMProvider
from ai_fw_audit.parser import parse_iptables_save
from ai_fw_audit.schemas import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "flawed-ruleset.txt"


class _MockProvider(LLMProvider):
    name = "mock"

    def chat_json(self, system: str, user: str) -> dict:
        # severity assignment is deliberately deterministic per anomaly class
        # so the test asserts behavior, not LLM output
        if "SHADOWING" in user:
            sev = "HIGH"
        elif "GENERALIZATION" in user:
            sev = "MEDIUM"
        elif "CORRELATION" in user:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        return {
            "severity": sev,
            "explanation": "mock explanation that is non-empty.",
            "suggested_fix": "mock suggested fix that is non-empty.",
        }


class _BadProvider(LLMProvider):
    """Returns malformed JSON to verify error fallback."""
    name = "bad"

    def chat_json(self, system: str, user: str) -> dict:
        return {"severity": "INVALID", "explanation": "", "suggested_fix": ""}


def test_enrich_pipeline_with_mock():
    chains = parse_iptables_save(FIXTURE.read_text())
    findings = analyze(chains)
    assert findings, "analyzer should produce findings on flawed ruleset"

    enriched = enrich(findings, _MockProvider())
    assert len(enriched) == len(findings)

    by_class: dict[str, list] = {}
    for e in enriched:
        by_class.setdefault(e.finding.anomaly_class.value, []).append(e)
        assert e.provider == "mock"
        assert e.explanation
        assert e.suggested_fix

    if "SHADOWING" in by_class:
        assert all(e.severity == Severity.HIGH for e in by_class["SHADOWING"])
    if "REDUNDANCY" in by_class:
        assert all(e.severity == Severity.LOW for e in by_class["REDUNDANCY"])


def test_enrich_handles_invalid_provider_output():
    chains = parse_iptables_save(FIXTURE.read_text())
    findings = analyze(chains)
    enriched = enrich(findings[:1], _BadProvider())
    assert len(enriched) == 1
    e = enriched[0]
    # Falls back to MEDIUM and an explanation that flags the LLM error.
    assert e.severity == Severity.MEDIUM
    assert "[LLM enrichment failed" in e.explanation
    assert e.provider == "bad"
