"""Abstract LLM provider interface.

Every concrete provider (Ollama, Anthropic, ...) implements `analyze_finding`.
The deterministic analyzer is the source of truth for *which* anomalies exist;
the LLM only enriches each finding with a severity, an explanation in plain
English, and a suggested fix.

We do NOT ask the LLM to find anomalies on its own — keeping the LLM out of
the discovery path is the central anti-marketing argument of this project.
"""

from __future__ import annotations

import abc
import json
import os
from typing import Optional

from pydantic import BaseModel, Field, ValidationError

from ..schemas import EnrichedFinding, Finding, Severity


class LLMResponse(BaseModel):
    """Raw structured output we expect every provider to return."""

    severity: Severity
    explanation: str = Field(min_length=1)
    suggested_fix: str = Field(min_length=1)


SYSTEM_PROMPT = """You are a senior network-security engineer reviewing the output of a deterministic firewall-rule analyzer.

The analyzer has already classified an anomaly between two iptables rules. Your job is NOT to find or change the classification. Your job is to:
  1. Assign a severity (LOW, MEDIUM, HIGH, or CRITICAL).
  2. Explain in plain English why this anomaly matters operationally (1-3 sentences).
  3. Suggest a concrete remediation in iptables terms (1-2 sentences, no commands needed).

Hard constraints:
- Do NOT invent rule indices or new rules.
- Do NOT contradict the deterministic classification.
- Do NOT speculate about rules you weren't shown.
- Output MUST be JSON exactly matching the schema {"severity", "explanation", "suggested_fix"} — no prose outside the JSON.

Severity rubric:
  - CRITICAL: directly enables external attacker access (e.g. ANY-source ACCEPT shadows deny).
  - HIGH: shadowed deny rule masking an intended security boundary.
  - MEDIUM: redundant or correlated rule that creates ambiguity but no immediate exposure.
  - LOW: cosmetic redundancy (e.g. exact duplicates with same action).
"""


def build_user_prompt(f: Finding) -> str:
    return (
        f"Anomaly class: {f.anomaly_class.value}\n"
        f"Chain: {f.chain}\n"
        f"Primary rule (idx {f.primary_idx}): {f.primary_raw}\n"
        f"Secondary rule (idx {f.secondary_idx}): {f.secondary_raw}\n"
        f"Deterministic explanation: {f.explanation}\n\n"
        "Return ONLY JSON: "
        '{"severity": "...", "explanation": "...", "suggested_fix": "..."}'
    )


class LLMProvider(abc.ABC):
    name: str

    @abc.abstractmethod
    def chat_json(self, system: str, user: str) -> dict: ...

    def analyze_finding(self, f: Finding) -> EnrichedFinding:
        try:
            raw = self.chat_json(SYSTEM_PROMPT, build_user_prompt(f))
            parsed = LLMResponse.model_validate(raw)
        except (ValidationError, json.JSONDecodeError, ValueError) as e:
            return EnrichedFinding(
                finding=f,
                severity=Severity.MEDIUM,
                explanation=f"[LLM enrichment failed: {type(e).__name__}: {e}]",
                suggested_fix="(no suggestion — provider error)",
                provider=self.name,
            )
        return EnrichedFinding(
            finding=f,
            severity=parsed.severity,
            explanation=parsed.explanation,
            suggested_fix=parsed.suggested_fix,
            provider=self.name,
        )


def get_provider(name: str = "auto") -> Optional[LLMProvider]:
    """Resolve a provider by name. `auto` tries Ollama first, then Anthropic.

    Returns None if no provider is reachable / configured.
    """
    name = (name or "auto").lower()

    if name in ("ollama", "auto"):
        try:
            from .ollama import OllamaProvider, ollama_reachable

            if ollama_reachable():
                return OllamaProvider()
        except Exception:
            pass
        if name == "ollama":
            return None

    if name in ("anthropic", "auto"):
        from ..secrets import get_secret

        if get_secret("ANTHROPIC_API_KEY"):
            try:
                from .anthropic_client import AnthropicProvider

                return AnthropicProvider()
            except Exception:
                return None
        if name == "anthropic":
            return None

    return None
