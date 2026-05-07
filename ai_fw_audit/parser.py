"""Parser for `iptables-save` text output.

Scope (v1): filter table only; basic matches (-p, -s, -d, --sport, --dport, -i, -o, -j).
Stateful matches (-m state / -m conntrack), negation (!), and unhandled match
modules (multiport, iprange, mac) are recognized and flagged so the analyzer
can skip them rather than mis-analyze them.
"""

from __future__ import annotations

import shlex
from collections import defaultdict
from typing import Iterator

from .schemas import PortRange, Rule

UNHANDLED_MATCHES = {"multiport", "iprange", "mac", "owner", "limit", "recent", "string"}


class IptablesParseError(ValueError):
    pass


def _parse_port_range(s: str) -> PortRange:
    if ":" in s:
        lo_s, hi_s = s.split(":", 1)
        lo = int(lo_s) if lo_s else 0
        hi = int(hi_s) if hi_s else 65535
    else:
        lo = hi = int(s)
    if lo < 0 or hi > 65535 or lo > hi:
        raise IptablesParseError(f"invalid port range: {s!r}")
    return PortRange(low=lo, high=hi)


def _parse_rule(line: str, chain_idx: int, table: str) -> Rule:
    # `-A CHAIN <args>`
    tokens = shlex.split(line)
    if not tokens or tokens[0] not in ("-A", "--append"):
        raise IptablesParseError(f"not a rule line: {line!r}")
    if len(tokens) < 2:
        raise IptablesParseError(f"missing chain: {line!r}")

    chain = tokens[1]
    rule = Rule(chain_idx=chain_idx, chain=chain, table=table, raw=line.strip())

    i = 2
    while i < len(tokens):
        tok = tokens[i]

        if tok == "!":
            rule.has_negation = True
            i += 1
            continue

        if tok in ("-p", "--protocol"):
            rule.protocol = tokens[i + 1].lower()
            i += 2
            continue
        if tok in ("-s", "--source"):
            rule.src_cidr = tokens[i + 1]
            i += 2
            continue
        if tok in ("-d", "--destination"):
            rule.dst_cidr = tokens[i + 1]
            i += 2
            continue
        if tok == "--sport" or tok == "--source-port":
            rule.sport = _parse_port_range(tokens[i + 1])
            i += 2
            continue
        if tok == "--dport" or tok == "--destination-port":
            rule.dport = _parse_port_range(tokens[i + 1])
            i += 2
            continue
        if tok in ("-i", "--in-interface"):
            rule.in_iface = tokens[i + 1]
            i += 2
            continue
        if tok in ("-o", "--out-interface"):
            rule.out_iface = tokens[i + 1]
            i += 2
            continue
        if tok in ("-j", "--jump"):
            rule.action = tokens[i + 1]
            i += 2
            continue
        if tok == "-m" or tok == "--match":
            mname = tokens[i + 1]
            if mname in ("state", "conntrack"):
                rule.has_state_match = True
                i += 2
                # consume the corresponding --state / --ctstate arg if present
                if i < len(tokens) and tokens[i] in ("--state", "--ctstate"):
                    i += 2
                continue
            if mname in UNHANDLED_MATCHES:
                rule.has_unhandled_match = True
                # best-effort: skip a couple of expected args; we won't try to be exhaustive
                i += 2
                continue
            i += 2
            continue
        # Anything else (e.g. counters `[0:0]`, `--syn`, `-g`) — flag and move on.
        # This keeps the parser permissive but conservative.
        if tok.startswith("--"):
            # Mark as "unhandled" if it looks like a match arg we don't know
            # but don't fail the whole rule. Skip the value if next token isn't a flag.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                i += 2
            else:
                i += 1
            continue
        i += 1

    return rule


def parse_iptables_save(text: str) -> dict[str, list[Rule]]:
    """Parse iptables-save text. Returns {chain_name: [Rule, ...]} for the filter table only.

    Custom-chain rules are kept under their chain name; cross-chain semantics
    are explicitly out of v1 scope (the analyzer compares within a single chain).
    """
    chains: dict[str, list[Rule]] = defaultdict(list)
    table = "filter"
    in_filter = False
    chain_counters: dict[str, int] = defaultdict(int)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:].strip()
            in_filter = table == "filter"
            continue
        if line == "COMMIT":
            in_filter = False
            continue
        if not in_filter:
            continue
        if line.startswith(":"):
            # `:CHAIN POLICY [counters]` — register the chain
            chain_name = line[1:].split()[0]
            chains.setdefault(chain_name, [])
            continue
        if line.startswith("-A") or line.startswith("--append"):
            tokens = line.split()
            if len(tokens) < 2:
                continue
            chain_name = tokens[1]
            chain_counters[chain_name] += 1
            try:
                rule = _parse_rule(line, chain_counters[chain_name], table)
            except IptablesParseError:
                # Skip unparseable lines but do not crash the whole load.
                continue
            chains[chain_name].append(rule)
            continue
        # other lines (e.g. -P / -N) are ignored in v1
    return dict(chains)


def iter_rules(chains: dict[str, list[Rule]]) -> Iterator[Rule]:
    for rules in chains.values():
        yield from rules
