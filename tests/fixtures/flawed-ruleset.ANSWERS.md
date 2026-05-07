# Ground truth: planted defects in `flawed-ruleset.txt`

Indices below are 1-based positions within the INPUT chain (only `-A INPUT` lines counted).

| INPUT idx | Rule | Status |
|-----------|------|--------|
| 1 | `-i lo -j ACCEPT` | clean |
| 2 | `-m state --state ESTABLISHED,RELATED -j ACCEPT` | clean (stateful — analyzer should skip pairwise comparison involving this rule and emit a SKIPPED note) |
| 3 | `-p tcp --dport 22 -j ACCEPT` | clean |
| 4 | `-p tcp --dport 22 -j ACCEPT` | **REDUNDANCY** (vs idx 3 — identical match, same action) |
| 5 | `-s 10.0.0.0/8 -j ACCEPT` | clean |
| 6 | `-s 10.1.0.0/16 -j DROP` | **SHADOWING** (vs idx 5 — match is subset, action differs) |
| 7 | `-p tcp --dport 80:90 -j ACCEPT` | clean |
| 8 | `-p tcp --dport 85:95 -j DROP` | **CORRELATION** (vs idx 7 — overlap on 85–90, neither subset, action differs) |
| 9 | `-p tcp --dport 8080 -j DROP` | clean (becomes part of generalization pair below) |
| 10 | `-p tcp --dport 8000:9000 -j ACCEPT` | **GENERALIZATION** (vs idx 9 — idx-9 match is strict subset of idx-10 match, action differs) |
| 11 | `-p udp --dport 53 -j ACCEPT` | clean |
| 12 | `-p udp --dport 53 -j DROP` | **SHADOWING** (vs idx 11 — identical match, action differs) |

## Expected analyzer output (recall target = 5/5)

The deterministic analyzer must emit at least these five findings (additional findings are acceptable but should be reasoned about in EVALUATION.md):

1. `REDUNDANCY` involving rule 4 (subsumed by rule 3)
2. `SHADOWING` involving rule 6 (shadowed by rule 5)
3. `CORRELATION` between rules 7 and 8
4. `GENERALIZATION` of rule 9 by rule 10
5. `SHADOWING` involving rule 12 (shadowed by rule 11)

## Notes for the LLM evaluation harness

- The LLM must NOT see this answer key. It only sees `flawed-ruleset.txt`.
- Hallucinated findings reference rule indices outside 1–12, or anomaly classes outside {SHADOWING, GENERALIZATION, CORRELATION, REDUNDANCY}.
- Scoring: TP if (anomaly_class, primary_idx, secondary_idx) matches a row above (order-tolerant). FP if not. FN if a row above is missing from the LLM output.
