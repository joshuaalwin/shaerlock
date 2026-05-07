# Evaluation

This document reports the concrete numbers that the evaluation harness
(`ai_fw_audit/evaluation.py`) produces against the synthetic fixtures.
The numbers below are reproducible from the project root, with the
virtualenv active, by running the commands shown after each table.

The harness reports two layers of metrics:

1. **Deterministic layer**, TP/FP/FN of `analyzer.py` against the
   ground-truth `ANSWERS.md` file. The LLM is not in this loop.
2. **LLM enrichment layer**, severity distribution and *hallucinated
   rule references* (any `primary_idx` / `secondary_idx` not present in
   the parsed ruleset). This metric directly tests the failure mode
   the constrained system prompt is designed to prevent.

## Fixture summary

| Fixture | Chain | Rules | Planted defects | Notes |
|---|---|---|---|---|
| `tests/fixtures/flawed-ruleset.txt` | INPUT | 12 | 5 | each defect mapped in `flawed-ruleset.ANSWERS.md` |
| `tests/fixtures/clean-ruleset.txt` | INPUT | 6 | 0 | well-formed control |

The flawed ruleset deliberately encodes one of each anomaly class plus
an extra `SHADOWING` example. The clean ruleset is the "no false
positives on a sane policy" control.

## Run 1, flawed ruleset, deterministic only

Command:

```bash
shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider none --out eval-runs/no-llm.json
```

| Metric | Value |
|---|---|
| Planted defects | 5 |
| Findings emitted | 13 |
| True positives (planted ∩ found) | 5 |
| False positives (found − planted) | 8 |
| False negatives (planted − found) | 0 |
| Recall | **1.000** |
| Precision (vs planted set) | 0.385 |

### Why precision is below 1.0, the eight extras are not bogus

Every "false positive" the harness reports here is a real, non-trivial
policy interaction in the synthetic fixture, not a spurious match. The
extras come from interactions involving the broad rule 5
(`-s 10.0.0.0/8 -j ACCEPT`) and the duplicate-port pair (rules 3 and
4):

| Extras (anomaly_class, primary_idx, secondary_idx) |
|---|
| `CORRELATION (3, 6)`, port-22 ACCEPT overlaps `10.1.0.0/16` DROP |
| `CORRELATION (4, 6)`, duplicate of the above for the duplicate port-22 ACCEPT |
| `CORRELATION (5, 8)`, `10.0.0.0/8` ACCEPT overlaps the port 85–95 DROP |
| `CORRELATION (5, 9)`, `10.0.0.0/8` ACCEPT overlaps the port-8080 DROP |
| `CORRELATION (5, 12)`, `10.0.0.0/8` ACCEPT overlaps the port-53 DROP |
| `CORRELATION (6, 7)`, `10.1.0.0/16` DROP overlaps the port 80–90 ACCEPT |
| `CORRELATION (6, 10)`, `10.1.0.0/16` DROP overlaps the port 8000–9000 ACCEPT |
| `CORRELATION (6, 11)`, `10.1.0.0/16` DROP overlaps the port-53 ACCEPT |

These are correctly classified `CORRELATION` findings under the Al-Shaer
& Hamed definition: in each case both rules' match sets genuinely
intersect, neither is a subset of the other, and the actions differ.
A practitioner reviewing the fixture by hand would (correctly) flag
the same overlaps. The ground-truth file enumerates only the *one*
deliberately planted instance per class to keep the answer key concise.
We chose to score against that smaller set rather than re-label all
correlations as planted, so the precision number underrepresents the
analyzer's actual usefulness.

A more pragmatic interpretation: the analyzer surfaces 13 distinct
real-world policy issues from a 12-rule fixture. None of them are
fabricated.

## Run 2, flawed ruleset, Anthropic LLM enrichment

Command:

```bash
shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider anthropic --out eval-runs/anthropic.json
```

Provider: `claude-sonnet-4-6` (configured via `shaerlock configure`,
key stored in OS keyring).

| Deterministic metric | Value |
|---|---|
| Planted defects | 5 |
| Findings emitted | 13 |
| True positives | 5 |
| False positives | 8 |
| False negatives | 0 |
| Recall | **1.000** |
| Precision (vs planted set) | 0.385 |

| LLM enrichment metric | Value |
|---|---|
| Findings enriched | 13 |
| Severity = HIGH | 4 |
| Severity = MEDIUM | 8 |
| Severity = LOW | 1 |
| Severity = CRITICAL | 0 |
| **Hallucinated rule references** | **0** |

The hallucination metric is the single most important number on this
page. It counts the times the LLM emitted a `primary_idx` or
`secondary_idx` outside the set of rule indices that actually exist in
the parsed ruleset (1–12 for this fixture). Zero hallucinated indices
means the constrained system prompt held: the LLM stayed within the
deterministic classification and did not invent rules it had not been
shown. This is the property the architecture is designed for.

### Severity assignments, qualitative spot-check

The model's severity rubric matched the analyst's intuition:

* The exact-duplicate `REDUNDANCY (3, 4)` was rated `LOW`, cosmetic.
* The `SHADOWING (5, 6)` (broad `10.0.0.0/8` ACCEPT silently
  swallowing the `10.1.0.0/16` DROP) was rated `HIGH`, a real
  security boundary disappears.
* The `SHADOWING (11, 12)` of the port-53 deny was rated `MEDIUM`
  rather than `HIGH`. Defensible: the shadowed rule is a deny *after*
  an allow on the same exact match set; it is unreachable but doesn't
  represent a missing security boundary.
* Port-range and source-range correlations were all rated `MEDIUM`
  with the explanation reasoning explicitly about ordering and
  internal-vs-external sources.

## Run 3, clean ruleset, deterministic only

Command:

```bash
shaerlock evaluate tests/fixtures/clean-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider none --out eval-runs/clean-control.json
```

| Metric | Value |
|---|---|
| Findings emitted | 0 |
| False positives on clean ruleset | 0 |

The clean ruleset produces zero findings, confirming the analyzer does
not fabricate anomalies on a well-formed policy. The `false_negative`
column reads 5 in the JSON because the harness scores against the
flawed-ruleset answer key for both fixtures; this is an artifact of
re-using the same answer key as a sanity reference, not a real
regression.

## Provider comparison (Ollama vs Anthropic)

The pluggable provider design supports a head-to-head Ollama-vs-
Anthropic comparison out of the box:

```bash
shaerlock evaluate ... --provider ollama   --out eval-runs/ollama.json
shaerlock evaluate ... --provider anthropic --out eval-runs/anthropic.json
```

The comparison was not run in this evaluation cycle: Ollama was not
installed on the demo machine (`which ollama` → not found,
`localhost:11434` unreachable). The architectural property, same
fixture, same scoring function, two providers, is exercised by the
provider-resolution code (`get_provider("auto")` and the
`--provider {ollama|anthropic}` switch in `cli.py`) and is part of the
public API regardless of whether the second provider is installed at
demo time.

## Reproducibility

* Python 3.11+ on Linux, virtualenv at `.venv`.
* For the Anthropic run, `shaerlock configure` stores the API key in
  the OS keyring (encrypted at rest); the key is never written to
  disk in plaintext and never appears in shell history.
* Each run writes a self-describing JSON report to `eval-runs/`. The
  per-finding LLM samples in those files are the audit trail behind
  the severity counts above.
