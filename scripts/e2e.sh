#!/usr/bin/env bash
# e2e.sh: end-to-end smoke test for shaerlock.
#
# Runs venv setup, install, pytest, every required CLI subcommand against
# the shipped fixtures, and the evaluation harness. Exits non-zero if any
# required step fails. Skipped (not failed) when prerequisites are absent:
#
#   * the Anthropic provider step is skipped when no key is configured.
#   * the fragmentation demo step is skipped when not running as root.
#
# Usage:
#   ./scripts/e2e.sh                 # required steps only
#   sudo ./scripts/e2e.sh            # also runs the fragmentation demo

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# ---------- helpers --------------------------------------------------------

GREEN="$(printf '\033[32m')"
RED="$(printf '\033[31m')"
YELLOW="$(printf '\033[33m')"
DIM="$(printf '\033[2m')"
RESET="$(printf '\033[0m')"

step() { printf '\n%s>> %s%s\n' "$DIM" "$1" "$RESET"; }
ok()   { printf '   %s[ok]%s    %s\n' "$GREEN" "$RESET" "$1"; }
skip() { printf '   %s[skip]%s  %s\n' "$YELLOW" "$RESET" "$1"; }
fail() { printf '   %s[fail]%s  %s\n' "$RED"  "$RESET" "$1"; }

results=()
record_pass() { results+=("PASS $1"); ok "$1"; }
record_skip() { results+=("SKIP $1 ($2)"); skip "$1 ($2)"; }
record_fail() { results+=("FAIL $1 ($2)"); fail "$1 ($2)"; FAILED=1; }
FAILED=0

# ---------- 1: venv --------------------------------------------------------

step "1. venv bootstrap"

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv || { record_fail "venv create" "python3 -m venv failed"; exit 1; }
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# Some user setups have a system pip earlier on PATH (Python 2.7 leftover).
# Always go through the venv's python -m pip.
.venv/bin/python -m ensurepip --upgrade >/dev/null 2>&1 || true
record_pass "venv ready at .venv"

# ---------- 2: install -----------------------------------------------------

step "2. pip install -e .[anthropic,dev]"

if .venv/bin/python -m pip install -e ".[anthropic,dev]" --quiet; then
  record_pass "editable install"
else
  record_fail "editable install" "pip install failed"
  exit 1
fi

# ---------- 3: pytest ------------------------------------------------------

step "3. pytest"

if .venv/bin/pytest --tb=no >/tmp/e2e-pytest.log 2>&1; then
  summary=$(grep -oE '[0-9]+ passed in [0-9.]+s' /tmp/e2e-pytest.log | tail -1)
  [[ -z "$summary" ]] && summary="passed"
  record_pass "pytest ($summary)"
else
  record_fail "pytest" "see /tmp/e2e-pytest.log"
fi

# ---------- 4: deterministic audit on flawed fixture -----------------------

step "4. shaerlock audit (deterministic, flawed fixture)"

OUT="/tmp/e2e-audit-flawed.json"
if .venv/bin/shaerlock audit tests/fixtures/flawed-ruleset.txt --no-llm \
        --json "$OUT" >/dev/null 2>&1; then
  # Verify against the JSON, not the rich-formatted terminal output
  # (rich truncates long class names with an ellipsis).
  missing=()
  for cls in SHADOWING GENERALIZATION CORRELATION REDUNDANCY; do
    if ! jq -e --arg c "$cls" '[.[].finding.anomaly_class] | index($c)' "$OUT" >/dev/null 2>&1; then
      missing+=("$cls")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    total=$(jq 'length' "$OUT")
    record_pass "every planted anomaly class present ($total findings)"
  else
    record_fail "audit (flawed)" "missing classes: ${missing[*]}"
  fi
else
  record_fail "audit (flawed)" "non-zero exit"
fi

# ---------- 5: deterministic audit on clean fixture ------------------------

step "5. shaerlock audit (deterministic, clean fixture)"

if .venv/bin/shaerlock audit tests/fixtures/clean-ruleset.txt --no-llm \
        >/tmp/e2e-audit-clean.log 2>&1; then
  if grep -q "no anomalies detected" /tmp/e2e-audit-clean.log; then
    record_pass "clean ruleset produced no findings"
  else
    record_fail "audit (clean)" "expected 'no anomalies detected'"
  fi
else
  record_fail "audit (clean)" "non-zero exit"
fi

# ---------- 6: deterministic evaluate (no LLM) -----------------------------

step "6. shaerlock evaluate (deterministic only)"

OUT="/tmp/e2e-no-llm.json"
if .venv/bin/shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
        tests/fixtures/flawed-ruleset.ANSWERS.md \
        --provider none --out "$OUT" >/dev/null 2>&1; then
  recall=$(jq -r '.deterministic.recall' "$OUT")
  fn=$(jq -r '.deterministic.false_negative' "$OUT")
  if [[ "$recall" == "1.0" ]] && [[ "$fn" == "0" ]]; then
    record_pass "recall=1.0, false_negative=0"
  else
    record_fail "evaluate (deterministic)" "recall=$recall fn=$fn"
  fi
else
  record_fail "evaluate (deterministic)" "non-zero exit"
fi

# ---------- 7: anthropic evaluate (optional) -------------------------------

step "7. shaerlock evaluate (anthropic)"

# Only attempt when a key is reachable.
if .venv/bin/python -c "from ai_fw_audit.secrets import get_secret; import sys; sys.exit(0 if get_secret('ANTHROPIC_API_KEY') else 1)" 2>/dev/null; then
  OUT="/tmp/e2e-anthropic.json"
  if .venv/bin/shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
          tests/fixtures/flawed-ruleset.ANSWERS.md \
          --provider anthropic --out "$OUT" >/dev/null 2>&1; then
    halluc=$(jq -r '(.llm.hallucinated_rule_refs | length)' "$OUT")
    enriched=$(jq -r '.llm.enriched_count' "$OUT")
    if [[ "$halluc" == "0" ]]; then
      record_pass "$enriched enriched, hallucinated_rule_refs=0"
    else
      record_fail "evaluate (anthropic)" "hallucinated_rule_refs=$halluc"
    fi
  else
    record_fail "evaluate (anthropic)" "non-zero exit"
  fi
else
  record_skip "evaluate (anthropic)" "ANTHROPIC_API_KEY not configured"
fi

# ---------- 8: fragmentation demo (optional, root-only) --------------------

step "8. shaerlock demo (fragmentation, requires root)"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  PCAP="/tmp/e2e-frag.pcap"
  if .venv/bin/shaerlock demo --pcap "$PCAP" >/tmp/e2e-demo.log 2>&1; then
    if [[ -s "$PCAP" ]] && capinfos -c "$PCAP" 2>/dev/null | grep -qE 'Number of packets:[[:space:]]*[1-9]'; then
      pkts=$(capinfos -c "$PCAP" | awk '/Number of packets:/ {print $NF}')
      record_pass "pcap captured ($pkts packets)"
    else
      record_fail "demo" "pcap missing or has 0 packets"
    fi
  else
    record_fail "demo" "non-zero exit, see /tmp/e2e-demo.log"
  fi
else
  record_skip "demo" "not running as root"
fi

# ---------- summary --------------------------------------------------------

echo
echo "================================================================"
echo "e2e summary"
echo "================================================================"
for r in "${results[@]}"; do
  echo "  $r"
done
echo

if [[ "$FAILED" -ne 0 ]]; then
  echo "${RED}e2e FAILED${RESET}"
  exit 1
fi
echo "${GREEN}e2e PASSED${RESET}"
