"""Pipeline glue: deterministic findings → LLM-enriched findings → evasion-linked."""

from __future__ import annotations

import sys
import time
from typing import Optional

from .evasion import attach_evasion
from .llm.base import LLMProvider
from .schemas import EnrichedFinding, Finding


def enrich(
    findings: list[Finding],
    provider: LLMProvider,
    progress_stream: Optional[object] = sys.stderr,
) -> list[EnrichedFinding]:
    """Run LLM enrichment on each finding, then attach the deterministic
    evasion mapping. Evasion is attached unconditionally because it is
    reproducible and does not depend on the LLM, so it is present even if
    LLM enrichment falls back to its error sentinel.

    Emits one-line progress markers to ``progress_stream`` so a long
    sequence of LLM calls does not appear hung. Pass ``progress_stream=None``
    to silence.
    """
    n = len(findings)
    out: list[EnrichedFinding] = []
    t0 = time.time()
    for idx, f in enumerate(findings, start=1):
        if progress_stream is not None:
            print(
                f"  [enrich {idx}/{n}] {f.anomaly_class.value} ({f.primary_idx}, {f.secondary_idx}) ...",
                file=progress_stream,
                flush=True,
            )
        t = time.time()
        e = provider.analyze_finding(f)
        if progress_stream is not None:
            print(
                f"  [enrich {idx}/{n}] {f.anomaly_class.value} severity={e.severity.value} ({time.time() - t:.1f}s)",
                file=progress_stream,
                flush=True,
            )
        out.append(attach_evasion(e))
    if progress_stream is not None:
        print(f"  [enrich done] {n} findings in {time.time() - t0:.1f}s", file=progress_stream, flush=True)
    return out
