# shaerlock

An iptables policy detective. Deterministic discovery, LLM-narrated
findings, evasion linkage.

I built this for the UMD ENPM693 Network Security final project.
`shaerlock` parses an `iptables-save` text dump, runs a deterministic
pairwise anomaly detector against it, optionally enriches each finding
through a pluggable LLM provider (local Ollama by default, Anthropic
Claude as a fallback), and links each finding to a concrete network
evasion technique with a MITRE ATT&CK reference. The headline numbers
on the synthetic fixture: 100% recall against planted defects, 0
hallucinated rule indices on 13 enriched findings.

The LLM does not find the bugs. A deterministic algorithm does. The
LLM only explains them, and the eval harness counts when it lies.

## Foundation vs contribution

The taxonomy is settled academic literature, like Codd's relational
model. What this project adds sits on top of it.

**What I inherit:**

The Al-Shaer & Hamed (2004) anomaly taxonomy: SHADOWING,
GENERALIZATION, CORRELATION, REDUNDANCY. Reaffirmed by Diekmann et
al. *J. Automated Reasoning* (2018) which formally verifies iptables
semantics on the same model. Recent LLM-policy work in
arXiv:2407.07930 (2024) is where the enrichment angle ties back to
the literature.

**What this project actually adds:**

* A deterministic detector and an LLM enricher that do not share a
  decision boundary, with hallucinated rule indices counted as a
  measured metric.
* A static `AnomalyClass → MITRE ATT&CK + citation` linkage table
  that turns each finding into an offensive narrative.
* A pluggable, offline-first provider design. Same fixture, same
  scoring function, two providers (Ollama and Anthropic), comparable
  output.
* A live pcap artifact tied to the SHADOWING finding via Ptacek-
  Newsham (1998).

## Quickstart on Kali or Debian

```bash
git clone https://github.com/joshuaalwin/shaerlock.git
cd shaerlock
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[anthropic,dev]"

# Run the deterministic analyzer only (no LLM, no API call):
shaerlock audit tests/fixtures/flawed-ruleset.txt --no-llm

# Run the test suite (28 tests, ~0.2s):
pytest -q
```

## Adding an Anthropic key (optional, for LLM enrichment)

```bash
shaerlock configure
# (paste key when prompted; input is hidden via getpass and stored in
# the OS keyring. Never on disk in plaintext, never in shell history)

shaerlock audit tests/fixtures/flawed-ruleset.txt --provider anthropic
```

Without a configured key (and without a reachable Ollama at
`localhost:11434`), `shaerlock` prints a warning and falls back to
the deterministic-only output. No API calls are made by default.

## Running the evaluation harness

```bash
mkdir -p eval-runs
shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider anthropic --out eval-runs/anthropic.json
```

Concrete numbers from the run on the synthetic fixture in this repo
are reported in `docs/EVALUATION.md`. Headline:

* deterministic recall against planted defects: **5/5 = 1.000**
* hallucinated LLM rule references: **0/13 enriched findings**
* clean control ruleset: **0 findings** (no false positives)

## Running the fragmentation evasion demo

```bash
sudo .venv/bin/python -m ai_fw_audit.cli demo
# or:  sudo ./demo/capture.sh
wireshark demo/frag.pcap
```

The demo emits a pair of overlapping IPv4 fragments to `127.0.0.1`
and captures them with `tcpdump`. The pcap visualizes the Ptacek-
Newsham fragmentation pattern linked to the SHADOWING anomaly class.
Localhost-only by construction. No real exfiltration. See
`demo/README.md` for the mechanism and ethical-scope notes.

## End-to-end test

```bash
./scripts/e2e.sh
```

Runs venv setup, install, pytest, every CLI subcommand against the
shipped fixtures, and the evaluation harness. Exits non-zero if any
required step fails. The Anthropic provider step is skipped when no
key is configured. The fragmentation demo step is skipped when not
running as root. See `docs/E2E.md` for the same flow as a human-
readable checklist with expected output.

## Layout

```
ai_fw_audit/        deterministic core, LLM providers, evasion table, CLI
demo/               scapy fragmentation demo + capture wrapper
docs/               PROJECT_DOSSIER, ARCHITECTURE, ANOMALY_TAXONOMY,
                    EVALUATION, REFERENCES, E2E
tests/              pytest suite + fixtures (flawed + clean rulesets +
                    ANSWERS)
eval-runs/          evaluation harness JSON output (the receipts cited
                    in docs/EVALUATION.md)
scripts/            e2e.sh
```

The Python import path is `ai_fw_audit/` for historical reasons. The
distribution name and the console script are `shaerlock`. This is
the same pattern `python-dateutil` uses (ships as `python-dateutil`,
imports as `dateutil`).

## Testing

```bash
pytest -q
```

The shipped suite (28 tests) covers parser correctness, deterministic
analyzer correctness against the planted defects in
`flawed-ruleset.ANSWERS.md`, evasion-mapping completeness, and an
offline path through the LLM evaluation harness.

## Limitations (read this before claiming results)

* Filter table only. NAT, mangle, and raw tables are out of scope.
* No cross-chain reachability. Custom-chain `JUMP` traversal is not
  modeled.
* Stateful conntrack rules (`-m state` / `-m conntrack`) are flagged
  for manual review and excluded from pairwise analysis.
* Negation `!` and unhandled match modules (`multiport`, `iprange`,
  `mac`, ...) are flagged and excluded.
* The fragmentation demo on Linux loopback *visualizes* the fragment
  pattern. It does not claim an end-to-end bypass on a real-world
  router-plus-host topology. See `demo/README.md`.
* The LLM, even constrained, can give a wrong severity. The
  evaluation harness reports severity distribution and hallucinated
  rule references so the tradeoff is auditable per-run rather than
  hidden.

The long version, with the full tradeoff list and the academic
lineage, lives in `docs/PROJECT_DOSSIER.md` (sections 9 and 10).

## License

MIT. Academic use, no warranty. Cite per `docs/REFERENCES.md`.
