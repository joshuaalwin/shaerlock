#!/usr/bin/env bash
# e2e.sh: end-to-end smoke test for shaerlock.
#
# Runs venv setup, install, pytest, every required CLI subcommand against
# the shipped fixtures, and the evaluation harness. Exits non-zero if any
# required step fails. Skipped (not failed) when prerequisites are absent:
#
#   * the Anthropic provider step is skipped when no key is accessible.
#     When running as root (sudo), the user keyring is not reachable, so
#     pass the key via ANTHROPIC_API_KEY env var:
#         sudo ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" ./scripts/e2e.sh
#   * the fragmentation demo step is skipped when not running as root.
#
# Usage:
#   ./scripts/e2e.sh                                          # required steps
#   sudo ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" ./scripts/e2e.sh  # full run

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# Use a per-run temp dir owned by the current user so there are no permission
# conflicts when the same script is run as root and then as a regular user.
RUNDIR=$(mktemp -d)
trap 'rm -rf "$RUNDIR"' EXIT

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

# When running as root via sudo, the Anthropic API key lives in the regular
# user's OS keyring which root cannot access (DBUS_SESSION_BUS_ADDRESS is not
# preserved through sudo). The Anthropic step is therefore expected to skip
# under sudo. Run the script as your normal user to exercise that step. The
# only step that genuinely needs root is the fragmentation demo.

# ---------- 1: venv --------------------------------------------------------

step "1. venv bootstrap"

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv || { record_fail "venv create" "python3 -m venv failed"; exit 1; }
fi
# shellcheck disable=SC1091
source .venv/bin/activate

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

if .venv/bin/pytest --tb=no >"$RUNDIR/pytest.log" 2>&1; then
  summary=$(grep -oE '[0-9]+ passed in [0-9.]+s' "$RUNDIR/pytest.log" | tail -1)
  [[ -z "$summary" ]] && summary="passed"
  record_pass "pytest ($summary)"
else
  record_fail "pytest" "see $RUNDIR/pytest.log"
fi

# ---------- 4: deterministic audit on flawed fixture -----------------------

step "4. shaerlock audit (deterministic, flawed fixture)"

AUDIT_JSON="$RUNDIR/audit-flawed.json"
if .venv/bin/shaerlock audit tests/fixtures/flawed-ruleset.txt --no-llm \
        --json "$AUDIT_JSON" >/dev/null 2>&1; then
  missing=()
  for cls in SHADOWING GENERALIZATION CORRELATION REDUNDANCY; do
    if ! jq -e --arg c "$cls" '[.[].finding.anomaly_class] | index($c)' "$AUDIT_JSON" >/dev/null 2>&1; then
      missing+=("$cls")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    total=$(jq 'length' "$AUDIT_JSON")
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
        >"$RUNDIR/audit-clean.log" 2>&1; then
  if grep -q "no anomalies detected" "$RUNDIR/audit-clean.log"; then
    record_pass "clean ruleset produced no findings"
  else
    record_fail "audit (clean)" "expected 'no anomalies detected'"
  fi
else
  record_fail "audit (clean)" "non-zero exit"
fi

# ---------- 6: deterministic evaluate (no LLM) -----------------------------

step "6. shaerlock evaluate (deterministic only)"

EVAL_JSON="$RUNDIR/eval-no-llm.json"
if .venv/bin/shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
        tests/fixtures/flawed-ruleset.ANSWERS.md \
        --provider none --out "$EVAL_JSON" >/dev/null 2>&1; then
  recall=$(jq -r '.deterministic.recall' "$EVAL_JSON")
  fn=$(jq -r '.deterministic.false_negative' "$EVAL_JSON")
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

# Key lookup: env var first (works under sudo), then keyring (works for
# the regular user).
if .venv/bin/python -c "from ai_fw_audit.secrets import get_secret; import sys; sys.exit(0 if get_secret('ANTHROPIC_API_KEY') else 1)" 2>/dev/null; then
  EVAL_ANTH_JSON="$RUNDIR/eval-anthropic.json"
  # 13 enrichments at 30s SDK timeout each = 390s worst case. Cap at 300s
  # wall clock. Show stderr (progress markers) so the user can see it
  # iterating instead of staring at a frozen line.
  if timeout 300 .venv/bin/shaerlock evaluate tests/fixtures/flawed-ruleset.txt \
          tests/fixtures/flawed-ruleset.ANSWERS.md \
          --provider anthropic --out "$EVAL_ANTH_JSON" >/dev/null; then
    halluc=$(jq -r '(.llm.hallucinated_rule_refs | length)' "$EVAL_ANTH_JSON")
    enriched=$(jq -r '.llm.enriched_count' "$EVAL_ANTH_JSON")
    if [[ "$halluc" == "0" ]]; then
      record_pass "$enriched enriched, hallucinated_rule_refs=0"
    else
      record_fail "evaluate (anthropic)" "hallucinated_rule_refs=$halluc"
    fi
  else
    rc=$?
    if [[ $rc -eq 124 ]]; then
      record_fail "evaluate (anthropic)" "timed out after 300s"
    else
      record_fail "evaluate (anthropic)" "non-zero exit ($rc)"
    fi
  fi
else
  record_skip "evaluate (anthropic)" "ANTHROPIC_API_KEY not reachable"
fi

# ---------- 8: fragmentation demo (optional, root-only) --------------------

step "8. shaerlock demo (fragmentation, requires root)"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  PCAP="$RUNDIR/frag.pcap"
  if .venv/bin/shaerlock demo --pcap "$PCAP" >"$RUNDIR/demo.log" 2>&1; then
    if [[ -s "$PCAP" ]] && capinfos -c "$PCAP" 2>/dev/null | grep -qE 'Number of packets:[[:space:]]*[1-9]'; then
      pkts=$(capinfos -c "$PCAP" | awk '/Number of packets:/ {print $NF}')
      # Copy pcap to a persistent location for Wireshark inspection.
      cp "$PCAP" /tmp/e2e-frag-latest.pcap 2>/dev/null || true
      record_pass "pcap captured ($pkts packets) — /tmp/e2e-frag-latest.pcap"
    else
      fail "demo log:" && cat "$RUNDIR/demo.log"
      record_fail "demo" "pcap missing or has 0 packets"
    fi
  else
    cat "$RUNDIR/demo.log"
    record_fail "demo" "non-zero exit (see above)"
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
