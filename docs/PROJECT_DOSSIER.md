# `shaerlock` Project Dossier

**Course:** UMD ENPM693 Network Security
**Project:** AI-Driven Firewall Rule Analysis and Evasion
**Working dir:** `/home/t3rminux/Desktop/UMD/ENPM693/Final-Project/`

This is the long-form write-up. It collects the architectural choices, the
dependency picks, the implementation notes, the tradeoffs I knowingly took,
and the references behind them. It is meant to be read on its own by someone
who has never opened the repo, and it is the source the slide deck will be
built from in the final phase.

---

## 1. Brief and framing

The instructor's feedback on the original submission was direct: go beyond
marketing-style material. A lot of products in this space pitch themselves
as "AI-powered firewall audit" while collapsing two distinct operations
into a single non-deterministic call: *finding* a misconfiguration, and
*explaining* it. The output of that kind of system is a black box you can
neither audit nor cite.

`shaerlock` is built on the opposite premise. Discovery is a
deterministic algorithm grounded in published academic work. The LLM is
constrained to enrichment only, and the evaluation harness measures its
behaviour separately. Each finding is then linked to a concrete network
evasion technique with a MITRE ATT&CK reference and an academic citation,
so the audit output is also an explanation of why a defender should care.

Locked decisions, taken from project memory:

* Defensive-primary angle. AI as auditor. Evasion appears as validation,
  not as the headline.
* Platform: `iptables` is the corpus. `pfSense` is referenced as a visual
  example only.
* AI model: pluggable provider. Default local Ollama (`llama3.1:8b`),
  fallback Anthropic API (`claude-sonnet-4-6`) via `ANTHROPIC_API_KEY` and
  the `--provider anthropic` flag. The demo runs offline by default and
  switches to a frontier model when an API key is configured.
* Citations: IEEE numbered.
* Live VM lab is out of scope. The evasion demo runs on `lo` via scapy.

### Why a 2004 paper is still the right foundation

A reader looking at the citation list could assume this project just
reimplements a 22-year-old paper. It does not. The taxonomy is settled
academic literature, in the same way Codd's relational model from 1970
is settled. What this project adds sits on top of it.

The actual lineage in `docs/REFERENCES.md`:

* Al-Shaer & Hamed 2004 (ref [1]) defines the anomaly taxonomy as a
  mathematical statement on rule match sets. Subset, superset,
  intersection, action equality. Math does not expire.
* Yuan et al. (FIREMAN) 2006 (ref [6]) extends the same model with
  BDD-based scaling for very large rulesets.
* Diekmann et al. *J. Automated Reasoning* 2018 (ref [5]) formally
  verifies iptables semantics on the same anomaly model. Peer-reviewed
  in 2018, not 2004.
* Lin et al. arXiv:2407.07930, 2024 (ref [12]) is the recent LLM-
  policy-audit reference that the enrichment angle in this project
  ties back to.

What I inherit from that lineage:

* The anomaly taxonomy itself: SHADOWING, GENERALIZATION, CORRELATION,
  REDUNDANCY.
* The within-chain pairwise comparison algorithm.

What this project actually adds:

* A deterministic detector and an LLM enricher that do not share a
  decision boundary, with hallucinated rule indices counted as a
  separate measured metric. The eval harness ran 13 enrichments and
  caught zero hallucinations. That is post-2024 framing, not 2004.
* A static `AnomalyClass → MITRE ATT&CK + citation` linkage table that
  turns each finding into an offensive narrative with a real ATT&CK
  reference (`T1599`, `T1562.004`).
* A pluggable, offline-first provider design. Same fixture, same
  scoring function, two providers (Ollama and Anthropic), comparable
  output. The architecture exists whether or not Ollama is installed
  on a given demo machine.
* A live pcap artifact tied to the `SHADOWING` finding via Ptacek-
  Newsham 1998. The pcap is the visual receipt for the linkage table.

What 2004 does not cover, and how this project handles each gap:

* Stateful conntrack semantics. Flagged and excluded from pairwise.
  See §10.
* Cross-chain JUMP traversal. Out of scope. Diekmann 2018 is the
  reference if anyone wants it modeled.
* Cloud security groups (unordered set evaluation). Out of scope. The
  corpus is iptables, not VPC ACLs.
* ML-on-firewall-logs. A different problem (anomalous traffic vs
  anomalous policy). Not a replacement for this work.

---

## 2. Architectural premise

The LLM does not discover anomalies. Discovery is a deterministic pairwise
algorithm derived from Al-Shaer & Hamed (2004). The LLM only enriches each
finding with a severity, a plain-English explanation, and a remediation
suggestion. That split is the load-bearing decision in the project, for
three reasons.

The first is auditability. A deterministic detector has a reproducible
output. The same ruleset always produces the same findings, and any
regression is a code change rather than a model change.

The second is citability. The detector implements the published Al-Shaer &
Hamed taxonomy. Every finding is traceable to a definition in the IEEE
INFOCOM 2004 paper.

The third is falsifiability of LLM behaviour. Because the deterministic
layer is the source of truth, the LLM's behaviour can be measured against
it. The evaluation harness counts hallucinated rule indices (any
`primary_idx`/`secondary_idx` not in the parsed ruleset) as a separate
metric. If that count is greater than zero, the LLM has regressed; the
auditor has not.

Diagrammatically:

```
        iptables-save text
                |
                v
        ai_fw_audit/parser.py          (regex / shlex tokenizer)
        chains: dict[str, list[Rule]]
                |
                v
        ai_fw_audit/analyzer.py        (Al-Shaer pairwise)
        list[Finding]                  (deterministic)
                |
                v
        ai_fw_audit/llm/{ollama,anthropic_client}.py
        constrained system prompt + JSON-mode
        list[EnrichedFinding]          (LLM, audited for hallucination)
                |
                v
        ai_fw_audit/evasion.py         (static AnomalyClass to MITRE table)
        list[EnrichedFinding]          (evasion fields populated)
                |
                v
        ai_fw_audit/cli.py             (typer + rich)
        audit | demo | evaluate | configure
```

---

## 3. Tech stack and why each piece is here

| Dependency | Version | Role | Why this one |
|---|---|---|---|
| Python | 3.11+ | runtime | type-hint semantics (`list[X]`, `X \| None`) and structural pattern matching simplify the analyzer |
| `pydantic` | >= 2.6 | schemas | first-class JSON validation, `model_copy` semantics, Enum support |
| `typer` | >= 0.12 | CLI | clean subcommand structure, automatic `--help`, type-driven argument parsing |
| `rich` | >= 13.7 | terminal output | tables and panels render cleanly in slides without re-formatting |
| `requests` | >= 2.31 | Ollama HTTP client | trivial to mock in tests; no async complexity for a single LLM call per finding |
| `scapy` | >= 2.5 | fragmentation demo | pure Python, programmatic control over fragment offset / id / overlap, plays well with `tcpdump` capture on `lo` |
| `python-dotenv` | >= 1.0 | config bootstrapping | a developer can drop a project-local `.env` for a quick session; the production path still uses the OS keyring |
| `keyring` | >= 25.0 | secret storage | OS-native encrypted storage. No plaintext secrets on disk |
| `SecretStorage` | >= 3.3 | Linux keyring backend | the freedesktop secret service used by GNOME Keyring / KWallet |
| `anthropic` | >= 0.40 | optional LLM | only imported when the Anthropic provider is selected, installed via the `[anthropic]` extra |
| `pytest`, `pytest-cov` | >= 8.0 / >= 5.0 | tests | shipped under the `[dev]` extra |

### 3.1 Alternatives I looked at and dropped

`better-iptables` for parsing. Three GitHub stars, last push 2023-12, no
documented match coverage. I wrote the parser by hand instead so I control
which match modules are recognized and which are flagged-and-skipped.

`audit-springbok` as a baseline. The first-pass research described it as
active Python; it is actually stale C from 2018. Discarded.

`google/capirca`. Generates ACLs forward, does not analyze existing rules.
Cited only.

`batfish/batfish`. Network-wide reachability analysis on Java. Powerful,
but its scope is whole-network topology, not host-firewall rule audit, and
it would need a Java toolchain and a configuration model the project does
not need.

`diekmann/Iptables_Semantics` (Isabelle/HOL formal verification). Peer-
reviewed and rigorous. The formal-methods overhead is disproportionate for
a 10-minute presentation, so I cite the paper rather than depending on the
artifact.

OpenAI or a generic LLM gateway. I avoided a marketing-style "swap in any
LLM" abstraction on purpose. Two providers are enough to demonstrate the
architecture, and a third would dilute the narrative without adding any
new measurement.

---

## 4. Module-by-module

### 4.1 `ai_fw_audit/schemas.py`

Pydantic models for `Rule`, `PortRange`, `Finding`, `EnrichedFinding`, plus
the `AnomalyClass` and `Severity` enums.

A few choices worth flagging.

`PortRange` carries containment, intersection, equality, and a wildcard
constructor. Centralizing port logic in the schema rather than the
analyzer keeps the analyzer's pairwise routine readable.

`Rule.is_skipped_from_pairwise()` is a method on the schema, not on the
analyzer. It encodes the project's explicit scope decisions: stateful
matches, negation, unhandled match modules, and loopback-only rules are
excluded from pairwise comparison. The analyzer delegates the "should I
look at this?" question to this method, and the CLI renders a separate
panel listing which rules were excluded and for which reason.

`Finding` records both *which* rule won the pair (the one whose action
stands) and *which* one was shadowed, redundant, or correlated.
Distinguishing the two indices is what lets the LLM author a remediation
that targets the correct rule.

### 4.2 `ai_fw_audit/parser.py`

A conservative tokenizer for `iptables-save` output. Scope: the `filter`
table only.

Tokenization uses `shlex.split` rather than a regex so that quoted match
arguments containing spaces do not corrupt the tokenizer. The recognized
arguments are deliberately the basic set: `-A`/`--append`,
`-p`/`--protocol`, `-s`/`--source`, `-d`/`--destination`,
`--sport`/`--source-port`, `--dport`/`--destination-port`,
`-i`/`--in-interface`, `-o`/`--out-interface`, `-j`/`--jump`. Anything
else is either flagged as "unhandled match" (`-m multiport`, `-m iprange`,
`-m mac`, `-m owner`, `-m limit`, `-m recent`, `-m string`) or flagged as
"stateful" (`-m state`, `-m conntrack`).

Per-chain rule indices are 1-based, and only `-A` lines are counted. This
matches the convention used in the ground-truth file
`flawed-ruleset.ANSWERS.md` and keeps `chain_idx` stable when policy
rules (`-P`) and chain declarations (`:`) are interleaved.

The parser is permissive on tokens it does not recognize. It skips with a
best-effort "advance one or two tokens" heuristic rather than aborting on
the line. That keeps real-world `iptables-save` dumps loadable even when
they contain match modules I do not model.

### 4.3 `ai_fw_audit/analyzer.py`

The deterministic core. For two rules `R_i` (earlier, smaller index) and
`R_j` (later, larger index) in the same chain, with match sets `M_i, M_j`
and actions `A_i, A_j`, the classification follows directly from the
`(j_in_i, i_in_j, same_action)` triple:

* `M_j ⊆ M_i` and `A_i = A_j` gives `REDUNDANCY` (R_j unreachable, same outcome).
* `M_j ⊆ M_i` and `A_i ≠ A_j` gives `SHADOWING` (R_j unreachable, different outcome).
* `M_i ⊊ M_j` and `A_i = A_j` gives `REDUNDANCY` (R_i is a foldable
  special case of R_j).
* `M_i ⊊ M_j` and `A_i ≠ A_j` gives `GENERALIZATION`.
* `M_i ∩ M_j ≠ ∅` and neither is a subset, with `A_i ≠ A_j`, gives
  `CORRELATION`.

Each match-set test is the conjunction of seven element-wise tests:
protocol, source CIDR, destination CIDR, sport, dport, in_iface,
out_iface. CIDRs use `ipaddress.subnet_of` and `overlaps`, so the routine
handles arbitrary IPv4 prefixes correctly.

The cascade in `_classify_pair` is exhaustive. It emits at most one
finding per ordered pair, and the precedence is identity-or-subset first,
then strict-superset, then intersection-without-subset.

Complexity is `O(n²)` per chain, which is fine for hand-managed firewalls
with hundreds of rules. I did not implement the BDD-based scaling tricks
from the FIREMAN paper. If the tool ever needs to scale to thousands of
rules per chain, the natural extension is to encode each rule's match set
as a BDD (or as a decision diagram in the spirit of Diekmann et al.) and
intersect rather than enumerate.

### 4.4 `ai_fw_audit/llm/`

A pluggable provider layer with one abstract method,
`chat_json(system, user) -> dict`, and a shared `analyze_finding`
implementation in `base.py` that does JSON validation and pydantic
schema-checking. Two concrete providers ship: `ollama.py` (HTTP JSON-mode
against `localhost:11434`) and `anthropic_client.py` (Anthropic SDK call
with code-fence-resilient JSON extraction).

The system prompt is the central guardrail. It does four things. It tells
the model the deterministic classification is fixed. It tells the model
not to invent rule indices. It tells the model to respond with a JSON
envelope matching `{severity, explanation, suggested_fix}` and nothing
else. And it provides a concrete severity rubric (LOW / MEDIUM / HIGH /
CRITICAL) tied to operational impact, so the model has an anchor for its
choices instead of relying on intuition.

This shape is the single biggest reason the Anthropic run produced zero
hallucinated rule indices on 13 enriched findings. The model was never
asked to identify rules; it was asked to characterize a pair the
deterministic layer had already identified.

`get_provider("auto")` resolves Ollama first (offline-by-default) and
falls back to Anthropic only if Ollama is unreachable and an API key is
configured. The Anthropic key is read from the OS keyring via
`secrets.py`. If the keyring is empty, a project-local `.env` is loaded
as a last resort. The `configure` CLI command stores the key with
`getpass`, so the secret never appears in shell history.

If LLM enrichment fails for any reason (network error, validation error,
decoding error), `analyze_finding` returns an `EnrichedFinding` with
severity `MEDIUM`, an explanation that names the exception class and
message, and `suggested_fix = "(no suggestion, provider error)"`. The
pipeline does not crash on a single failed enrichment. It degrades to
deterministic-plus-error output.

### 4.5 `ai_fw_audit/evasion.py`

A static, hardcoded `AnomalyClass to EvasionMapping` table. Each entry
has a technique name, a MITRE ATT&CK ID, a MITRE technique name, an
academic citation, and a multi-sentence attack-narrative paragraph.

The mapping is deliberately not LLM-generated. Reproducibility and
citation fidelity matter more than novelty here: the attack narratives
are the part of the writeup that has to defend itself against a
follow-up question from the grader, and a model-generated narrative
cannot be cited.

The four mappings:

| AnomalyClass | Technique | MITRE | Citation |
|---|---|---|---|
| `SHADOWING` | IP fragmentation evasion of a shadowed deny rule | `T1599` Network Boundary Bridging | Ptacek & Newsham, 1998 |
| `GENERALIZATION` | Match-set widening (trigger broader allow over narrow deny) | `T1599` | Al-Shaer & Hamed, 2004 |
| `CORRELATION` | Order-dependent rule ambiguity exploitation | `T1599` | Al-Shaer & Hamed, 2004 |
| `REDUNDANCY` | Audit-gap abuse via redundant duplicate rules | `T1562.004` Impair Defenses | Wool, 2004 |

`attach_evasion(enriched)` is a one-line `model_copy` that populates the
`evasion_technique` and `evasion_attck_id` fields on an existing
`EnrichedFinding`. It runs unconditionally, so the offensive linkage is
present even when LLM enrichment falls back to its error sentinel.

### 4.6 `ai_fw_audit/secrets.py`

OS keyring wrapper. Lookup precedence: keyring, then environment
variable, then `.env` (already merged into env by the CLI bootstrap).
Storage uses `keyring.set_password`. The `secrets` module is invoked
from `cli.configure`, which uses `getpass` for the prompt so the key is
not echoed and is not written to shell history.

I considered three alternatives.

A plaintext file under `~/.config/shaerlock/`. Simple, but one shared
screenshot leaks the key. Rejected.

An environment variable only. Forces the user to manage a long-lived
secret in their shell config. Acceptable as a fallback, not as the
primary path.

An encrypted blob with a user-supplied passphrase. Re-implements what
`keyring` already does, with worse cross-platform behaviour. Rejected.

The keyring path also has an explicit removal flow
(`shaerlock configure --delete`) so the secret can be cleaned up after
the demo without leaving residue in the OS credential store.

### 4.7 `ai_fw_audit/evaluation.py`

The grading harness. It reads `ANSWERS.md`, runs the pipeline, and prints
a structured report covering two layers.

Deterministic: planted, found, true-positive, false-positive,
false-negative, recall, precision.

LLM: enriched count, severity distribution, hallucinated rule
references, and up to five sample explanations.

The report is also written as JSON for reproducibility. The
hallucination check is a set-membership test: every
`(primary_idx, secondary_idx)` pair the LLM emits is checked against the
set of indices actually present in the parsed ruleset. Anything outside
is recorded with the anomaly class.

### 4.8 `ai_fw_audit/cli.py`

`typer`-based CLI with four subcommands.

`audit` parses, analyzes, optionally enriches and links, and renders to
a rich-formatted table. `--json` writes structured findings.

`evaluate` runs the full pipeline against an `ANSWERS.md` file and
prints TP/FP/FN, severity distribution, and hallucinated-rule-index
counts.

`demo` runs the IPv4 fragmentation demo on the loopback interface and
writes a `pcap`.

`configure` stores or deletes the Anthropic API key in the OS keyring.

The audit output renders the evasion column in both the no-LLM and the
enriched paths. The no-LLM path uses `evasion.map_finding` so there is
no LLM round-trip. The enriched path uses the populated
`EnrichedFinding` fields. JSON output for the no-LLM path includes the
full evasion record (technique, MITRE id, MITRE name, citation,
narrative) so the artifact is self-describing without the human-readable
column.

### 4.9 `ai_fw_audit/demo_runner.py` and `demo/`

The fragmentation demo orchestration. The runner emits three packets to
`127.0.0.1:<port>` over a raw socket.

Fragment 1 carries the UDP header (`sport=4444`, `dport=port`) plus 8
bytes of `'A'` payload, with `IP id = 0xBEEF`, `MF=1`, `frag=0`.

Fragment 2 carries 56 bytes of `'B'` payload, same `id`, `MF=0`,
`frag=1` (offset = 8 bytes).

The third packet is the overlap: `id = 0xBEF0`, `MF=1`, `frag=0`,
carrying `'X'*8` at the same offset as fragment 1. This is the
visualization of the late-arriving overlap whose role in the canonical
Ptacek-Newsham mechanism is to overwrite the transport header on a
downstream stack that prefers later fragments during reassembly.

`tcpdump` is spawned in a context manager and its `.pcap` output lands
in `demo/frag.pcap` by default. The runner refuses to run without root
(`os.geteuid() != 0`) rather than silently degrading. A standalone
`demo/frag_demo.py` wraps the same runner for users who want to invoke
the demo without going through the typer CLI, and a `demo/capture.sh`
shell wrapper provides the one-line reproduction path.

### 4.10 `tests/`

28 tests, organized as follows.

`test_parser.py`: 8 tests covering rule count, indexing,
protocol/port/CIDR/interface extraction, and the state-match flagging
that drives pairwise exclusion.

`test_analyzer.py`: 8 tests against the planted defects in
`ANSWERS.md`. One test per planted class plus a composite test that
asserts 100% recall against the full answer set, plus another that
asserts the clean ruleset produces zero findings.

`test_enricher.py`: an offline LLM stub plus integration with the
evasion attachment.

`test_evaluation_offline.py`: the harness end-to-end with a stubbed
provider.

`test_evasion.py`: 8 tests asserting every `AnomalyClass` has a mapping,
every mapping has a well-formed MITRE ATT&CK ID (`Txxxx[.xxx]`), every
narrative is non-trivially long, and `attach_evasion` does not mutate
its input.

---

## 5. The anomaly taxonomy, formalized

For each rule
`R = (proto, src, dst, sport, dport, in_iface, out_iface, action)`, the
*match set* `M(R)` is the set of all packets whose header fields
satisfy every component of `R`. A wildcard component (`None`) is the
universe of values for that component. Element-wise:

* `proto`: `M_proto(R) = {R.proto}` if specified, else
  `{tcp, udp, icmp, ...}`.
* `src`, `dst`: the CIDR's IP block, else `0.0.0.0/0`.
* `sport`, `dport`: the inclusive interval `[low, high]`, else
  `[0, 65535]`.
* `in_iface`, `out_iface`: the literal interface, else any.

`M(R) = M_proto × M_src × M_dst × M_sport × M_dport × M_in × M_out`.

For two rules in the same chain, `R_i` (earlier) and `R_j` (later), with
actions `A_i, A_j`:

```
M_j ⊆ M_i ∧ A_i = A_j   →  REDUNDANCY (subsuming duplicate)
M_j ⊆ M_i ∧ A_i ≠ A_j   →  SHADOWING
M_i ⊊ M_j ∧ A_i = A_j   →  REDUNDANCY (foldable special case)
M_i ⊊ M_j ∧ A_i ≠ A_j   →  GENERALIZATION
M_i ∩ M_j ≠ ∅, neither subset, A_i ≠ A_j  →  CORRELATION
```

The fifth Al-Shaer & Hamed class, *irrelevance* (orphan rules whose
match set cannot be reached given the network topology), is out of
scope. It needs a topology model the project does not maintain.

---

## 6. LLM design choices

### 6.1 The constrained system prompt

The system prompt does not ask the LLM to find anomalies. It tells the
LLM the deterministic classification is fixed and asks it to assign a
severity (LOW, MEDIUM, HIGH, CRITICAL), explain in plain English why
the anomaly matters operationally, and suggest a concrete remediation
in iptables terms.

It also imposes hard constraints. Do not invent rule indices. Do not
contradict the deterministic classification. Do not speculate about
rules you weren't shown. Output JSON only.

The severity rubric is embedded in the prompt so the model has a
concrete anchor for its choices. That shape is the single biggest
reason the Anthropic run produced zero hallucinated rule indices on 13
enriched findings.

### 6.2 JSON-mode enforcement

Both providers enforce JSON output.

Ollama uses the `format: "json"` option on `/api/chat`.

Anthropic relies on the system-prompt directive plus a code-fence-
resilient parser that strips ``` and `json` prefixes before
`json.loads`.

If the JSON does not validate against the `LLMResponse` pydantic model,
`analyze_finding` returns a sentinel `EnrichedFinding` with the
exception captured in the explanation field. The pipeline does not
crash on a malformed response.

### 6.3 Provider comparison as substance

The pluggable provider design is itself part of the academic content.
Same fixture, same scoring function, same constrained prompt, two
providers. Any divergence (severity calibration, hallucination rate,
explanation length) is observable and reportable in `EVALUATION.md`. In
this evaluation cycle only the Anthropic provider was exercised,
because Ollama was not installed on the demo machine. The architectural
property is exercised by `get_provider("auto")` and the `--provider`
switch, and is part of the public API regardless of whether Ollama is
present at demo time.

---

## 7. The fragmentation demo and its ethical scope

The demo is the offensive counterpart to the `SHADOWING` finding. It
emits a pair of overlapping IPv4 fragments on `lo`, captures them with
`tcpdump`, and writes a `.pcap` that opens cleanly in Wireshark.

What the audience sees in Wireshark:

* Two `IPv4 Fragment` rows with the same `Identification: 0xBEEF` and a
  reassembled UDP packet whose data is `AAAAAAAA` followed by 56 `B`
  bytes.
* One additional `IPv4 Fragment` with `Identification: 0xBEF0` carrying
  `XXXXXXXX`.

Why it lives on `lo`. There is no external network involvement. The
payload is a synthetic `'A'*8 + 'B'*56` byte string, no real
exfiltration. The "victim" is a short-lived UDP socket bound to
`127.0.0.1`.

A caveat I want to be honest about. Linux loopback does not implement
the same insertion / evasion ambiguity as a real-world stack-plus-NIC
combination, so this demo *visualizes* the fragment-overlap pattern. It
does not prove an end-to-end bypass on a real-world topology. Showing
the bypass would need a router-with-stateless-filter setup in a VM lab,
which is explicitly out of scope.

Root is required for raw sockets and `tcpdump`. The runner refuses to
run without it rather than silently degrading.

---

## 8. Evaluation methodology and concrete numbers

The harness runs three configurations against the two shipped fixtures
(`flawed-ruleset.txt`, `clean-ruleset.txt`) and reports two layers of
metrics: deterministic (TP/FP/FN/recall/precision) and LLM (severity
distribution and hallucinated rule references).

### 8.1 Run 1: flawed ruleset, deterministic only

| Metric | Value |
|---|---|
| Planted defects | 5 |
| Findings emitted | 13 |
| True positives | 5 |
| False positives | 8 |
| False negatives | 0 |
| Recall | **1.000** |
| Precision (vs planted set) | 0.385 |

The eight "false positives" are not bogus. Each one is a correctly-
classified `CORRELATION` finding in the synthetic fixture: in every
case both rules' match sets genuinely intersect, neither is a subset of
the other, and the actions differ. The ground-truth file enumerates
only one deliberately planted instance per class, to keep the answer
key concise. Scoring against that smaller set underrepresents the
analyzer's actual usefulness. The analyzer surfaces 13 distinct real
policy issues in a 12-rule fixture, and none of them are fabricated.

### 8.2 Run 2: flawed ruleset, Anthropic enrichment

Provider: `claude-sonnet-4-6`. Key stored in OS keyring via
`shaerlock configure`.

| Deterministic metric | Value |
|---|---|
| Planted defects | 5 |
| Findings emitted | 13 |
| True positives | 5 |
| False positives | 8 |
| False negatives | 0 |
| Recall | **1.000** |
| Precision | 0.385 |

| LLM enrichment metric | Value |
|---|---|
| Findings enriched | 13 |
| Severity = HIGH | 4 |
| Severity = MEDIUM | 8 |
| Severity = LOW | 1 |
| Severity = CRITICAL | 0 |
| **Hallucinated rule references** | **0** |

The severity assignments matched my own intuition on the fixture.

The exact-duplicate `REDUNDANCY (3, 4)` was rated `LOW`, which is the
right call because it is cosmetic.

The `SHADOWING (5, 6)` (a broad `10.0.0.0/8` ACCEPT silently swallowing
a `10.1.0.0/16` DROP) was rated `HIGH`. A real security boundary
disappears in that pair, so I would have called it `HIGH` too.

The `SHADOWING (11, 12)` (a deny rule shadowed by an allow on the same
exact match set) came back `MEDIUM` rather than `HIGH`. Defensible: the
rule is unreachable, but it does not represent a missing security
boundary.

Port-range and source-range correlations were rated `MEDIUM` with
explanations that reasoned explicitly about ordering and internal-
versus-external sources.

### 8.3 Run 3: clean ruleset, deterministic only

| Metric | Value |
|---|---|
| Findings emitted | 0 |

Zero findings on a well-formed policy confirms the analyzer does not
fabricate anomalies on clean input.

---

## 9. Tradeoffs I knowingly accepted

The pairwise routine is `O(n²)` per chain. Fine for hand-managed
firewalls, documented above as an explicit decision. The BDD-based
extension path is the answer for thousands-of-rules workloads.

Cross-chain reachability is not modeled. Custom-chain rules are kept
under their chain name and compared within that chain only. Modeling
JUMP traversal correctly needs the kind of semantics work Diekmann et
al. did in Isabelle/HOL, and that is too heavy for this scope.

Stateful semantics are flagged, not modeled. Rules with `-m state` or
`-m conntrack` are excluded from pairwise comparison. Modeling
conntrack correctly needs a state machine that is out of scope for v1.
Getting it wrong silently would be worse than excluding the rule and
announcing the exclusion.

Loopback rules are excluded from pairwise. Including them produced a
flood of low-value `CORRELATION` findings in early runs. The exclusion
is a pragmatic tradeoff and is logged in the CLI's "rules excluded"
panel.

LLM as enricher, not detector. This is the project's central thesis.
The cost is that the LLM cannot surface anomalies the deterministic
algorithm misses. The benefit is that the deterministic algorithm
cannot lie.

No DNS-tunneling demo. The mapping for `REDUNDANCY` references protocol
tunneling, but I did not build an iodine-based tunnel demo. Time-
budget call. The linkage is documented in the evasion table and in
`docs/REFERENCES.md`.

Two providers, not five. More providers would dilute the comparison
narrative. Two is enough to demonstrate the abstraction.

Hardcoded evasion table. Reproducibility and citation fidelity matter
more than novelty here. An LLM-generated narrative cannot be cited.

---

## 10. Drawbacks and known limitations

If you are going to act on this tool's output, here is what you should
know first.

It only looks at the `filter` table. NAT, mangle, and raw are out of
scope. A misconfiguration that lives in `nat` (for example, a
permissive `DNAT` to an internal host) will not be flagged.

Within-chain only. No cross-chain reachability. A rule that jumps to a
custom chain whose semantics undo the parent chain's intent is
invisible to the analyzer.

Conntrack semantics are absent. Stateful matches are flagged for
manual review. The analyzer cannot tell you whether your
`ESTABLISHED,RELATED` exemption is correctly scoped.

Match modules are unhandled: `multiport`, `iprange`, `mac`, `owner`,
`limit`, `recent`, `string`. The parser flags them and the analyzer
skips them. A policy that relies entirely on unhandled modules will
produce zero findings.

Negation is flagged, not analyzed. Set complements are not modeled.

Loopback rules are excluded. `-i lo` and `-o lo` rules are skipped from
pairwise comparison.

The LLM can give a wrong severity. Even with a constrained prompt and a
rubric, severity assignment is judgment. The evaluation harness reports
the severity distribution and the hallucination count so a per-run
audit is possible, but a single miscalibrated severity is not a
catchable failure on its own.

The fragmentation demo is a visualization on `lo`. It does not claim an
end-to-end bypass on a real-world topology. The pcap shows the fragment
pattern, not a real defense being defeated.

The eight "false positives" in the deterministic run are not bogus.
They are real correlation findings the answer key does not enumerate.
A reader who looks only at the precision number will misread the
analyzer's quality.

There is no formal verification of the analyzer. Diekmann et al.
Isabelle/HOL is the gold standard there. I cite it but do not
implement it. The correctness guarantees here come from the test suite
against the planted defects, not from a formal proof.

Single-machine, single-host. The project does not model a network of
firewalls. Inter-firewall anomalies (the original Al-Shaer & Hamed
paper covers them too) are out of scope.

---

## 11. Reproducibility

A fresh `git clone` on a stock Kali should run cleanly through:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[anthropic,dev]"
pytest -q                                                    # 28/28 passes
shaerlock audit tests/fixtures/flawed-ruleset.txt --no-llm
shaerlock configure                                        # interactive
shaerlock audit tests/fixtures/flawed-ruleset.txt --provider anthropic
shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider anthropic --out eval-runs/anthropic.json
sudo .venv/bin/python -m ai_fw_audit.cli demo                # writes demo/frag.pcap
wireshark demo/frag.pcap
```

Every external dependency is pinned to a minimum version in
`pyproject.toml`. The Ollama path is exercised by `get_provider("auto")`
and the `--provider ollama` switch. Running it needs
`curl -fsSL https://ollama.com/install.sh | sh` and
`ollama pull llama3.1:8b` on the demo machine.

---

## 12. References

IEEE numbered. Each reference is cited from one of the documents in
this dossier or from a code comment.

[1] E. Al-Shaer and H. Hamed, "Discovery of Policy Anomalies in
Distributed Firewalls," in *Proc. IEEE INFOCOM*, Hong Kong, 2004,
pp. 2605-2616.

[2] E. Al-Shaer, H. Hamed, R. Boutaba, and M. Hasan, "Conflict
Classification and Analysis of Distributed Firewall Policies," *IEEE
J. Sel. Areas Commun.*, vol. 23, no. 10, pp. 2069-2084, Oct. 2005.

[3] A. Wool, "A Quantitative Study of Firewall Configuration Errors,"
*IEEE Computer*, vol. 37, no. 6, pp. 62-67, Jun. 2004.

[4] T. H. Ptacek and T. N. Newsham, "Insertion, Evasion, and Denial of
Service: Eluding Network Intrusion Detection," Secure Networks, Inc.,
Tech. Rep., Jan. 1998.

[5] C. Diekmann, L. Hupel, J. Michaelis, M. Haslbeck, and G. Carle,
"Verified iptables Firewall Analysis and Verification," *J. Automated
Reasoning*, vol. 61, no. 1-4, pp. 191-242, Jun. 2018.

[6] L. Yuan, J. Mai, Z. Su, H. Chen, C.-N. Chuah, and P. Mohapatra,
"FIREMAN: A Toolkit for FIREwall Modeling and ANalysis," in *Proc.
IEEE Symp. Security and Privacy*, Berkeley, CA, May 2006,
pp. 199-213.

[7] MITRE Corporation, "MITRE ATT&CK," 2024. Online:
https://attack.mitre.org/. Specific techniques cited:

* `T1599`, *Network Boundary Bridging.*
* `T1562.004`, *Impair Defenses: Disable or Modify System Firewall.*
* `T1572`, *Protocol Tunneling.* Referenced in the evasion-table notes
  for `REDUNDANCY` but not implemented as a demo.

[8] Netfilter Project, "iptables-save / iptables-restore, Linux manual
page," in *Linux man-pages*. Online:
https://man7.org/linux/man-pages/man8/iptables-save.8.html

[9] Netgate, "pfSense Documentation, Scrub / Packet Normalization,"
2024. Online:
https://docs.netgate.com/pfsense/en/latest/firewall/scrub.html

[10] Ollama, "Ollama, local LLM runtime," 2024. Online:
https://ollama.com

[11] Anthropic, "Claude API, Message Format and Structured Outputs,"
2024. Online: https://docs.anthropic.com/en/api/messages

[12] T. Lin, J. Sun, J. Yang, et al., "From Code to Compromise:
Evaluating Large Language Models for Security Policy Audit and
Generation," *arXiv:2407.07930*, 2024.

[13] M. Haslbeck and G. Carle, "Iptables Semantics, Isabelle/HOL formal
verification artifact," GitHub repository, 2024. Cited only, not
depended on.

[14] J. Nevo, "better-iptables, Python iptables-save parser," GitHub
repository, 2023. Reviewed and rejected (I wrote my own parser).

[15] M. Y. (martimy), "firewall_policy_analyzer," GitHub repository,
2025. Reviewed as reference, closest active prior art implementing
Al-Shaer-style detection in Python.

[16] Conix Security, "audit-springbok," GitHub repository, 2018.
Reviewed and rejected (stale C, mis-described in initial research).

[17] Google, "capirca," GitHub repository. Cited only, generates ACLs
forward rather than analyzing existing rules.

[18] Batfish project, "Batfish," GitHub repository. Cited only,
network-wide topology analysis rather than host-firewall rule audit.
