# End-to-end walkthrough

This is the demo-day checklist. It walks through every step
`scripts/e2e.sh` automates, with the expected output pasted inline so
a grader can verify by eye and a presenter can step through it live.

The script form (`./scripts/e2e.sh`) is the safety net; this document
is the narrative. They run the same checks.

---

## Prereqs

* Kali or Debian, Python 3.11 or newer.
* A working `python3` on `PATH`.
* Optional: `ANTHROPIC_API_KEY` configured (for the LLM step).
* Optional: `sudo` (for the fragmentation demo step).

If you cloned fresh, every command below runs from the repo root.

---

## 1. Bootstrap the venv and install

```bash
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install -e ".[anthropic,dev]"
```

Expected: pip prints "Successfully installed shaerlock-0.1.0 ..."
plus the resolved dependency tree. The console script
`shaerlock` is registered at `.venv/bin/shaerlock`.

```bash
shaerlock --help
```

Expected: a typer help block listing four subcommands:
`audit`, `demo`, `evaluate`, `configure`.

---

## 2. Run the test suite

```bash
pytest -q
```

Expected output ends with:

```
............................                                             [100%]
28 passed in 0.04s
```

What this covers: parser, deterministic analyzer, evasion mapping,
offline LLM evaluation harness.

---

## 3. Deterministic audit on the flawed fixture

```bash
shaerlock audit tests/fixtures/flawed-ruleset.txt --no-llm
```

Expected: a rich-formatted Anomalies table containing entries for
every planted-defect class:

| class | chain | primary | secondary | evasion (MITRE) |
|---|---|---|---|---|
| `REDUNDANCY` | INPUT | 3 | 4 | Audit-gap abuse (T1562.004) |
| `SHADOWING` | INPUT | 5 | 6 | IP fragmentation evasion (T1599) |
| `CORRELATION` | INPUT | 7 | 8 | Order-dependent ambiguity (T1599) |
| `GENERALIZATION` | INPUT | 10 | 9 | Match-set widening (T1599) |
| `SHADOWING` | INPUT | 11 | 12 | IP fragmentation evasion (T1599) |

Plus 8 additional `CORRELATION` rows that involve the broad
`-s 10.0.0.0/8` rule. These are *real* findings, discussed in
`docs/EVALUATION.md` §1.

The rich library may render long class names with an ellipsis
(`GENERALIZATI…`). For machine-readable output, add `--json
/path/to/out.json`.

---

## 4. Deterministic audit on the clean fixture

```bash
shaerlock audit tests/fixtures/clean-ruleset.txt --no-llm
```

Expected: the rich panel shows the ruleset metadata, no excluded-
rules table, and the final line:

```
no anomalies detected
```

This is the "no false positives on a sane policy" control. If this
step prints findings, the analyzer is fabricating them.

---

## 5. Evaluation harness, deterministic only

```bash
mkdir -p eval-runs
shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider none --out eval-runs/no-llm.json
```

Expected table:

```
        Deterministic vs ground
                truth
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ metric         ┃ value ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ planted        │     5 │
│ found          │    13 │
│ true_positive  │     5 │
│ false_positive │     8 │
│ false_negative │     0 │
│ recall         │   1.0 │
│ precision      │ 0.385 │
└────────────────┴───────┘
```

The `recall == 1.0` line is the headline. The 8 false positives are
real correlation findings the answer key does not enumerate; see
`docs/EVALUATION.md` §1 for the breakdown.

---

## 6. Evaluation harness, Anthropic provider (optional)

Skip this step if you have not run `shaerlock configure`. Otherwise:

```bash
shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
    tests/fixtures/flawed-ruleset.ANSWERS.md \
    --provider anthropic --out eval-runs/anthropic.json
```

Expected, in addition to the deterministic table:

```
    LLM enrichment (anthropic)
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ metric                 ┃ value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ enriched               │    13 │
│ severity[HIGH]         │     4 │
│ severity[LOW]          │     1 │
│ severity[MEDIUM]       │     8 │
│ hallucinated_rule_refs │     0 │
└────────────────────────┴───────┘
```

The `hallucinated_rule_refs == 0` line is the metric the constrained
system prompt is designed to deliver. If this is non-zero, the LLM
invented a rule index, and the architecture has regressed.

---

## 7. Fragmentation evasion demo (requires root)

```bash
sudo .venv/bin/python -m ai_fw_audit.cli demo
# or:
sudo ./demo/capture.sh
```

Expected: a cyan panel announcing `shaerlock demo: IPv4 fragmentation
evasion (loopback only)`, three "sending fragment" log lines, and a
`capture written to demo/frag.pcap` confirmation.

Verify the pcap with `capinfos`:

```bash
capinfos demo/frag.pcap
```

Expected: at least one packet, file format `pcap`. Then open it in
Wireshark:

```bash
wireshark demo/frag.pcap
```

In Wireshark you should see:

* Two `IPv4 Fragment` rows with the same `Identification: 0xBEEF`
  and a reassembled UDP packet whose data is `AAAAAAAA` followed
  by 56 `B` bytes.
* One additional `IPv4 Fragment` with `Identification: 0xBEF0`
  carrying `XXXXXXXX`.

This is the offensive counterpart to the SHADOWING finding linked
to MITRE ATT&CK `T1599`. See `demo/README.md` for the mechanism and
ethical-scope notes.

---

## Pass criteria

The full run is considered passing when:

1. `pytest -q` reports `28 passed`.
2. Step 3 lists every planted-defect class.
3. Step 4 prints `no anomalies detected`.
4. Step 5 reports `recall == 1.0` and `false_negative == 0`.
5. Step 6 (if attempted) reports `hallucinated_rule_refs == 0`.
6. Step 7 (if attempted) produces a non-empty pcap.

The automation in `scripts/e2e.sh` enforces these as exit-code
checks. Steps 6 and 7 are optional and are reported as `SKIP` when
their prerequisites are absent.

---

## Reproducibility

* All fixtures (`tests/fixtures/`) and their answer key are part of
  the repo. The flawed and clean rulesets do not depend on any
  external state.
* Eval output JSON files live under `eval-runs/` and are tracked in
  the repo. They are the receipts cited in `docs/EVALUATION.md`.
* The Anthropic step uses `claude-sonnet-4-6` by default. Override
  with `AI_FW_AUDIT_ANTHROPIC_MODEL=<model>` in the environment.
* The Ollama step (not run by default) uses `llama3.1:8b`. Override
  with `AI_FW_AUDIT_OLLAMA_MODEL=<model>`.
