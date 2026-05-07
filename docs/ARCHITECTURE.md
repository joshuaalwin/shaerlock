# Architecture, `shaerlock`

## Why split deterministic analysis from LLM enrichment

The single most important architectural decision in this project is that
the LLM does *not* discover anomalies. Discovery is performed by a
deterministic pairwise algorithm derived from Al-Shaer & Hamed (2004) [1].
The LLM only enriches each finding with severity, a plain-English
operational explanation, and a remediation suggestion.

This split exists because of a specific failure mode the project is
designed to refute: marketing-style "AI-powered" security tooling that
collapses *what* the policy says and *what to do about it* into a single
non-deterministic call. The instructor's brief explicitly required the
project go beyond marketing material; an architecture that lets the LLM
invent rule indices or claim non-existent shadowing relations would
violate that constraint, and so the LLM is constrained to a structured
JSON envelope and audited for hallucinated rule indices in the evaluation
harness (`docs/EVALUATION.md`).

## Module map

```
            iptables-save text
                    │
                    ▼
            ai_fw_audit/parser.py
              regex / shlex tokenizer
              → dict[chain → list[Rule]]
                    │
                    ▼
            ai_fw_audit/analyzer.py
              pairwise Al-Shaer detector
              ⊆, ⊊, ∩ on (proto, src, dst, sport, dport, in/out iface)
              → list[Finding]
                    │
                    ▼
            ai_fw_audit/llm/{ollama,anthropic_client}.py
              constrained system prompt, JSON-mode
              → severity, explanation, suggested_fix
                    │
                    ▼
            ai_fw_audit/evasion.py
              static AnomalyClass → MITRE ATT&CK + citation table
              → EnrichedFinding with evasion fields populated
                    │
                    ▼
            ai_fw_audit/cli.py (typer + rich)
              audit | demo | evaluate | configure
```

### `parser.py`

A conservative tokenizer for `iptables-save` output, scope-limited to the
`filter` table. It recognizes the basic match arguments (`-p`, `-s`,
`-d`, `--sport`, `--dport`, `-i`, `-o`, `-j`) and explicitly *flags*
matches it does not model (`-m state`, `-m conntrack`, `multiport`,
`iprange`, `mac`, …) so the analyzer can skip them rather than mis-analyze
them. Negation (`!`) is also flagged. Per-chain rule indices are 1-based
(only `-A` lines counted), matching the convention in `ANSWERS.md`.

### `analyzer.py`

For every pair of rules `(r_i, r_j)` with `i < j` in the same chain, the
analyzer computes:

* `match_subset(a, b)`, true iff `M_b ⊆ M_a`. Element-wise containment
  on each tuple component, with CIDRs compared via `ipaddress.subnet_of`,
  ports via interval containment, and protocols/interfaces via
  literal-or-wildcard.
* `match_intersects(a, b)`, true iff `M_a ∩ M_b ≠ ∅`.

The finding class follows directly from the tuple `(j_in_i, i_in_j,
same_action)` per `docs/ANOMALY_TAXONOMY.md`. Stateful, negated, unhandled-
match-module, and loopback-only rules are excluded from pairwise
comparison; they are reported in the "rules excluded from pairwise
analysis" panel so the operator sees what was skipped and why.

### `llm/`

Pluggable provider layer with a single abstract method `chat_json(system,
user) -> dict` and a shared `analyze_finding` implementation in `base.py`
that handles JSON validation and pydantic schema-checking.

Both providers share the same constrained system prompt: the LLM is told
explicitly that the deterministic classification is fixed, that it must
not invent rule indices, and that it must respond with a JSON envelope
matching `{severity, explanation, suggested_fix}`. Hallucinated rule
indices are surfaced by the evaluation harness as a separate metric.

`get_provider("auto")` resolves Ollama first (offline-by-default) and
falls back to Anthropic only if Ollama is not reachable and an API key
is configured. The Anthropic API key is read from the OS keyring (via
`secrets.py`); if absent there, the `.env` file in the project root is
loaded as a fallback. The `configure` CLI command stores the key with
`getpass`, so the secret never appears in shell history.

### `evasion.py`

Static, hardcoded `AnomalyClass → EvasionMapping` table. The mapping is
intentionally not LLM-generated, because reproducibility and citation
fidelity matter more than novelty here. Every entry has a MITRE ATT&CK
ID, an academic citation, and a short attack-narrative paragraph.

### `cli.py`

The CLI is `typer`-based with three first-class subcommands plus
`configure`:

* `audit`, parse, analyze, optionally enrich and link, render to a
  rich-formatted table; optional `--json` writes the structured findings
  for the writeup.
* `evaluate`, runs the full pipeline against an `ANSWERS.md` ground-
  truth file and prints TP/FP/FN, severity distribution, and
  hallucinated-rule-index counts.
* `demo`, runs the IPv4 fragmentation demo on the loopback interface
  and writes a `pcap` (see `demo/README.md`).

## Out-of-scope (v1), explicit

* NAT, mangle, raw tables.
* Cross-chain reachability and custom-chain `-j JUMP` traversal.
* Stateful conntrack semantics. Rules with `-m state` / `-m conntrack`
  are flagged for manual review and skipped from pairwise comparison.
* Negation `!` is flagged and skipped.
* Match modules `multiport`, `iprange`, `mac`, `owner`, `limit`,
  `recent`, `string`, parsed but treated as "unhandled" and excluded
  from pairwise comparison.
* The "irrelevance" / orphan anomaly class (Al-Shaer & Hamed [1]), it
  requires network topology context, which is out of scope.
* Live multi-VM lab; pfSense rule analysis. The project is single-host,
  iptables-corpus only.
* DNS tunneling / protocol tunneling demo. Mentioned in the evasion table
  for `REDUNDANCY` but not implemented as an artifact.

## Pluggable provider rationale

The default-Ollama, fallback-Anthropic design lets the demonstration run
fully offline on a stock Kali box (no API call ever leaves the machine)
while still enabling a comparative evaluation against a frontier model
when an API key is configured. The provider comparison is itself
academic substance: a small local model and a frontier model share the
same constrained prompt, the same fixture, and the same scoring
function, and any divergence is observable and reportable in
`EVALUATION.md`.
