"""
tests/ambiguity/test_type_coercion.py

Tests for type coercion and enum value handling.

Verifies that string representations of enum values are accepted/rejected
consistently and that type boundaries are well-defined:
- BlastRadius enum: valid string values, invalid string values
- DecisionType enum: valid values, invalid values
- confidence as int (coercion from int to float)
- Boolean fields: reversibility and delegation
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, os.path.join(_HERE, "../conformance"))
sys.path.insert(0, _HERE)

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

    _spec = _iu.spec_from_file_location(
        "_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"),
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings

warnings.filterwarnings("ignore")

import pytest
from shani import BlastRadius, DecisionType
from shani.schemas.decision import EvidenceItem

from framework import ConformanceSuite
from ambiguity_fixtures import make_proposal


# ---------------------------------------------------------------------------
# 1. BlastRadius enum coercion
# ---------------------------------------------------------------------------


def test_blast_radius_valid_string_values(suite: ConformanceSuite) -> None:
    """All four BlastRadius string values must be accepted by the schema."""
    suite._section("1. BlastRadius valid string values")
    valid = ["isolated", "limited", "significant", "critical"]
    for val in valid:
        p = make_proposal(blast_radius=BlastRadius(val))
        suite.must_pass(
            f"coercion:blast_radius_{val}",
            p.blast_radius == BlastRadius(val),
            f"blast_radius={val!r} accepted",
            f"got {p.blast_radius}",
        )


def test_blast_radius_invalid_string_rejected(suite: ConformanceSuite) -> None:
    """An unrecognized BlastRadius string must raise ValueError."""
    suite._section("1b. BlastRadius invalid string rejected")
    raised = False
    try:
        BlastRadius("extreme")
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "coercion:blast_radius_invalid",
        raised,
        "invalid BlastRadius string raises",
    )


def test_blast_radius_case_sensitivity(suite: ConformanceSuite) -> None:
    """BlastRadius values are case-sensitive: 'Limited' must not equal 'limited'."""
    suite._section("1c. BlastRadius case sensitivity")
    raised = False
    try:
        BlastRadius("Limited")
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "coercion:blast_radius_case",
        raised,
        "BlastRadius is case-sensitive",
    )


# ---------------------------------------------------------------------------
# 2. DecisionType enum coercion
# ---------------------------------------------------------------------------


def test_decision_type_valid_values(suite: ConformanceSuite) -> None:
    """All DecisionType members must be constructible from their string value."""
    suite._section("2. DecisionType valid values")
    for member in DecisionType:
        p = make_proposal(decision_type=DecisionType(member.value))
        suite.must_pass(
            f"coercion:decision_type_{member.value}",
            p.decision_type == member,
            f"decision_type={member.value!r} accepted",
            f"got {p.decision_type}",
        )


def test_decision_type_invalid_string_rejected(suite: ConformanceSuite) -> None:
    """An unrecognized DecisionType string must raise ValueError."""
    suite._section("2b. DecisionType invalid string rejected")
    raised = False
    try:
        DecisionType("arbitrary_action")
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "coercion:decision_type_invalid",
        raised,
        "invalid DecisionType string raises",
    )


# ---------------------------------------------------------------------------
# 3. confidence float coercion
# ---------------------------------------------------------------------------


def test_confidence_int_coercion(suite: ConformanceSuite) -> None:
    """confidence=1 (int) must be accepted."""
    suite._section("3. confidence int coercion to float")
    p = make_proposal(confidence=1)
    suite.must_pass(
        "coercion:confidence_int",
        p.confidence == 1,
        "confidence=1 accepted as float-equivalent",
        f"got {p.confidence!r}",
    )


def test_confidence_above_one_rejected(suite: ConformanceSuite) -> None:
    """confidence > 1.0 must be rejected by the schema."""
    suite._section("3b. confidence > 1.0 rejected")
    raised = False
    try:
        make_proposal(confidence=1.1)
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "coercion:confidence_above_one",
        raised,
        "confidence=1.1 rejected",
    )


def test_confidence_below_zero_rejected(suite: ConformanceSuite) -> None:
    """confidence < 0.0 must be rejected by the schema."""
    suite._section("3c. confidence < 0.0 rejected")
    raised = False
    try:
        make_proposal(confidence=-0.1)
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "coercion:confidence_below_zero",
        raised,
        "confidence=-0.1 rejected",
    )


# ---------------------------------------------------------------------------
# 4. Boolean field coercion
# ---------------------------------------------------------------------------


def test_reversibility_is_strictly_boolean(suite: ConformanceSuite) -> None:
    """reversibility=True and reversibility=False are distinct and correctly stored."""
    suite._section("4. reversibility boolean")
    p_true = make_proposal(reversibility=True)
    p_false = make_proposal(reversibility=False)
    suite.must_pass(
        "coercion:reversibility_true",
        p_true.reversibility is True,
        "reversibility=True stored as True",
    )
    suite.must_pass(
        "coercion:reversibility_false",
        p_false.reversibility is False,
        "reversibility=False stored as False",
    )


def test_delegation_is_strictly_boolean(suite: ConformanceSuite) -> None:
    """delegation=True and delegation=False are distinct and correctly stored."""
    suite._section("4b. delegation boolean")
    p_true = make_proposal(delegation=True)
    p_false = make_proposal(delegation=False)
    suite.must_pass(
        "coercion:delegation_true",
        p_true.delegation is True,
        "delegation=True stored as True",
    )
    suite.must_pass(
        "coercion:delegation_false",
        p_false.delegation is False,
        "delegation=False stored as False",
    )


# ---------------------------------------------------------------------------
# 5. EvidenceItem confidence coercion
# ---------------------------------------------------------------------------


def test_evidence_confidence_edge_values(suite: ConformanceSuite) -> None:
    """EvidenceItem confidence must accept 0.0 and 1.0 at the extremes."""
    suite._section("5. EvidenceItem confidence edge values")
    item_zero = EvidenceItem(source="s", content="c", confidence=0.0)
    item_one = EvidenceItem(source="s", content="c", confidence=1.0)
    suite.must_pass(
        "coercion:evidence_confidence_zero",
        item_zero.confidence == 0.0,
        "EvidenceItem confidence=0.0 accepted",
    )
    suite.must_pass(
        "coercion:evidence_confidence_one",
        item_one.confidence == 1.0,
        "EvidenceItem confidence=1.0 accepted",
    )


def test_evidence_confidence_above_one_rejected(suite: ConformanceSuite) -> None:
    """EvidenceItem confidence > 1.0 must be rejected."""
    suite._section("5b. EvidenceItem confidence > 1.0 rejected")
    raised = False
    try:
        EvidenceItem(source="s", content="c", confidence=1.01)
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "coercion:evidence_confidence_above_one",
        raised,
        "EvidenceItem confidence=1.01 rejected",
    )
