from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AnomalyClass(str, Enum):
    SHADOWING = "SHADOWING"
    GENERALIZATION = "GENERALIZATION"
    CORRELATION = "CORRELATION"
    REDUNDANCY = "REDUNDANCY"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PortRange(BaseModel):
    low: int = Field(ge=0, le=65535)
    high: int = Field(ge=0, le=65535)

    @classmethod
    def any_port(cls) -> "PortRange":
        return cls(low=0, high=65535)

    def is_any(self) -> bool:
        return self.low == 0 and self.high == 65535

    def contains(self, other: "PortRange") -> bool:
        return self.low <= other.low and other.high <= self.high

    def intersects(self, other: "PortRange") -> bool:
        return not (self.high < other.low or other.high < self.low)

    def equals(self, other: "PortRange") -> bool:
        return self.low == other.low and self.high == other.high

    def render(self) -> str:
        if self.is_any():
            return "any"
        if self.low == self.high:
            return str(self.low)
        return f"{self.low}-{self.high}"


class Rule(BaseModel):
    """A single iptables rule, normalized for analysis."""

    chain_idx: int  # 1-based position within its chain (only -A lines counted)
    chain: str
    table: str = "filter"

    protocol: Optional[str] = None  # "tcp", "udp", "icmp", "all"; None = wildcard
    src_cidr: Optional[str] = None  # CIDR string; None = any
    dst_cidr: Optional[str] = None
    sport: PortRange = Field(default_factory=PortRange.any_port)
    dport: PortRange = Field(default_factory=PortRange.any_port)
    in_iface: Optional[str] = None
    out_iface: Optional[str] = None

    action: str = "ACCEPT"  # ACCEPT/DROP/REJECT/RETURN/LOG/<chain-name>

    has_state_match: bool = False
    has_negation: bool = False
    has_unhandled_match: bool = False  # multiport, iprange, mac, etc.

    raw: str = ""  # original line, for display

    def is_skipped_from_pairwise(self) -> bool:
        """Rules excluded from pairwise anomaly detection in v1.

        Skipped:
          - stateful matches (-m state / -m conntrack) — semantics not modeled
          - negation (`!`) — set complements not modeled
          - unhandled match modules (multiport, iprange, mac, ...)
          - loopback-only rules (-i lo / -o lo) — universally trusted in practice;
            including them produces a flood of low-value correlation findings
        """
        if self.has_state_match or self.has_negation or self.has_unhandled_match:
            return True
        if self.in_iface == "lo" or self.out_iface == "lo":
            return True
        return False


class Finding(BaseModel):
    """A deterministic anomaly finding (pre-LLM-enrichment)."""

    anomaly_class: AnomalyClass
    primary_idx: int  # the rule that "wins" the pair (the one whose action stands)
    secondary_idx: int  # the rule that is shadowed/redundant/correlated
    chain: str
    explanation: str  # short, deterministic, human-readable
    primary_raw: str
    secondary_raw: str


class EnrichedFinding(BaseModel):
    """A finding after LLM enrichment."""

    finding: Finding
    severity: Severity
    explanation: str  # LLM-authored
    suggested_fix: str  # LLM-authored
    evasion_technique: Optional[str] = None
    evasion_attck_id: Optional[str] = None
    provider: str  # "ollama" / "anthropic" / "none"
