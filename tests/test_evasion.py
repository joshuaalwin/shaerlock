"""Tests for the evasion-mapping layer."""

from __future__ import annotations

import re

import pytest

from ai_fw_audit.evasion import EVASION_TABLE, attach_evasion, map_finding
from ai_fw_audit.schemas import (
    AnomalyClass,
    EnrichedFinding,
    Finding,
    Severity,
)


def _make_finding(cls: AnomalyClass) -> Finding:
    return Finding(
        anomaly_class=cls,
        primary_idx=1,
        secondary_idx=2,
        chain="INPUT",
        explanation="test",
        primary_raw="-A INPUT -j ACCEPT",
        secondary_raw="-A INPUT -j DROP",
    )


def _make_enriched(cls: AnomalyClass) -> EnrichedFinding:
    return EnrichedFinding(
        finding=_make_finding(cls),
        severity=Severity.MEDIUM,
        explanation="x",
        suggested_fix="y",
        provider="none",
    )


def test_every_anomaly_class_has_a_mapping():
    """Every member of AnomalyClass must have an evasion mapping."""
    for cls in AnomalyClass:
        assert cls in EVASION_TABLE, f"missing evasion mapping for {cls}"


def test_mapping_fields_are_well_formed():
    """Each mapping must have non-empty fields and a MITRE ATT&CK ID."""
    attck_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    for cls, m in EVASION_TABLE.items():
        assert m.technique
        assert attck_re.match(m.mitre_attck_id), (
            f"{cls.value} ATT&CK ID {m.mitre_attck_id!r} doesn't match Txxxx[.xxx]"
        )
        assert m.mitre_attck_name
        assert m.citation
        assert len(m.narrative) > 80, f"{cls.value} narrative is suspiciously short"


@pytest.mark.parametrize("cls", list(AnomalyClass))
def test_map_finding_returns_mapping(cls: AnomalyClass):
    f = _make_finding(cls)
    m = map_finding(f)
    assert m is EVASION_TABLE[cls]


def test_attach_evasion_populates_fields_without_mutating_input():
    e = _make_enriched(AnomalyClass.SHADOWING)
    assert e.evasion_technique is None
    assert e.evasion_attck_id is None

    enriched = attach_evasion(e)
    expected = EVASION_TABLE[AnomalyClass.SHADOWING]
    assert enriched.evasion_technique == expected.technique
    assert enriched.evasion_attck_id == expected.mitre_attck_id

    # Original is unchanged (model_copy does not mutate).
    assert e.evasion_technique is None
    assert e.evasion_attck_id is None


def test_shadowing_maps_to_fragmentation_per_ptacek_newsham():
    """Spot-check the headline mapping the demo will visualize."""
    m = EVASION_TABLE[AnomalyClass.SHADOWING]
    assert "fragmentation" in m.technique.lower()
    assert "Ptacek" in m.citation
