"""
tests/ambiguity/test_field_defaults.py

Tests for default field behavior in the Shani schema.

Verifies that omitted optional fields default to the expected values and do
not introduce ambiguity or bypass safety invariants:
- DecisionScope with all defaults
- EvidenceItem with confidence=None
- DelegationRules zero-value defaults (no delegation permitted)
- DecisionProposal scope and evidence defaults
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

from shani.schemas.decision import (
    DecisionScope,
    DelegationRules,
    EvidenceItem,
)

from framework import ConformanceSuite
from ambiguity_fixtures import make_proposal, make_evaluator, make_posture


# ---------------------------------------------------------------------------
# 1. DecisionScope defaults
# ---------------------------------------------------------------------------


def test_decision_scope_defaults(suite: ConformanceSuite) -> None:
    """DecisionScope() must default to empty collections and None."""
    suite._section("1. DecisionScope defaults")
    scope = DecisionScope()
    suite.must_pass(
        "defaults:scope_asset_ids",
        scope.asset_ids == [],
        "asset_ids defaults to []",
        f"got {scope.asset_ids}",
    )
    suite.must_pass(
        "defaults:scope_resource_types",
        scope.resource_types == [],
        "resource_types defaults to []",
        f"got {scope.resource_types}",
    )
    suite.must_pass(
        "defaults:scope_geographic_boundary",
        scope.geographic_boundary is None,
        "geographic_boundary defaults to None",
        f"got {scope.geographic_boundary}",
    )
    suite.must_pass(
        "defaults:scope_max_affected_count",
        scope.max_affected_count is None,
        "max_affected_count defaults to None",
        f"got {scope.max_affected_count}",
    )


def test_default_scope_accepted_by_evaluator(suite: ConformanceSuite) -> None:
    """A proposal with a default DecisionScope must be accepted without error."""
    suite._section("1b. Default scope accepted by evaluator")
    ev = make_evaluator()
    proposal = make_proposal(scope=DecisionScope())
    result = ev.evaluate(proposal)
    suite.must_pass(
        "defaults:scope_evaluator_ok",
        result is not None,
        "default scope does not cause evaluation error",
    )


# ---------------------------------------------------------------------------
# 2. EvidenceItem with confidence=None
# ---------------------------------------------------------------------------


def test_evidence_item_confidence_none(suite: ConformanceSuite) -> None:
    """EvidenceItem.confidence=None is valid."""
    suite._section("2. EvidenceItem confidence=None")
    item = EvidenceItem(source="sensor", content="reading", confidence=None)
    suite.must_pass(
        "defaults:evidence_confidence_none",
        item.confidence is None,
        "confidence=None accepted",
        f"got {item.confidence}",
    )


def test_evidence_item_no_signature_fields(suite: ConformanceSuite) -> None:
    """EvidenceItem without signature/signed_by must default both to None."""
    suite._section("2b. EvidenceItem signature fields default to None")
    item = EvidenceItem(source="sensor", content="reading", confidence=0.8)
    suite.must_pass(
        "defaults:evidence_signature_none",
        item.signature is None,
        "signature defaults to None",
        f"got {item.signature}",
    )
    suite.must_pass(
        "defaults:evidence_signed_by_none",
        item.signed_by is None,
        "signed_by defaults to None",
        f"got {item.signed_by}",
    )


# ---------------------------------------------------------------------------
# 3. DelegationRules zero-value defaults
# ---------------------------------------------------------------------------


def test_delegation_rules_defaults(suite: ConformanceSuite) -> None:
    """DelegationRules() must default to 'no delegation permitted'."""
    suite._section("3. DelegationRules defaults")
    rules = DelegationRules()
    suite.must_pass(
        "defaults:deleg_sub_decisions",
        rules.allowed_sub_decisions == [],
        "allowed_sub_decisions defaults to []",
        f"got {rules.allowed_sub_decisions}",
    )
    suite.must_pass(
        "defaults:deleg_max_child_dsal",
        rules.max_child_dsal == 0,
        "max_child_dsal defaults to 0",
        f"got {rules.max_child_dsal}",
    )
    suite.must_pass(
        "defaults:deleg_max_depth",
        rules.max_depth == 0,
        "max_depth defaults to 0",
        f"got {rules.max_depth}",
    )
    suite.must_pass(
        "defaults:deleg_max_children",
        rules.max_children == 0,
        "max_children defaults to 0",
        f"got {rules.max_children}",
    )
    suite.must_pass(
        "defaults:deleg_not_permitted",
        rules.delegation_permitted is False,
        "delegation_permitted is False with all-zero defaults",
        f"got delegation_permitted={rules.delegation_permitted}",
    )


def test_partial_delegation_rules_not_permitted(suite: ConformanceSuite) -> None:
    """Setting only some delegation fields must not accidentally enable delegation."""
    suite._section("3b. Partial DelegationRules not permitted")
    rules = DelegationRules(allowed_sub_decisions=["remediation"])
    suite.must_pass(
        "defaults:partial_deleg_not_permitted",
        rules.delegation_permitted is False,
        "sub_decisions set but max_child_dsal=0 → not permitted",
        f"got delegation_permitted={rules.delegation_permitted}",
    )


# ---------------------------------------------------------------------------
# 4. DecisionProposal defaults
# ---------------------------------------------------------------------------


def test_proposal_decision_id_auto_generated(suite: ConformanceSuite) -> None:
    """Two proposals without explicit decision_id must have different IDs."""
    suite._section("4. Proposal decision_id auto-generated")
    p1 = make_proposal()
    p2 = make_proposal()
    suite.must_pass(
        "defaults:proposal_unique_id",
        p1.decision_id != p2.decision_id,
        "decision_id is unique per proposal",
        f"both got: {p1.decision_id}",
    )


def test_proposal_scope_defaults_to_empty(suite: ConformanceSuite) -> None:
    """DecisionProposal.scope defaults to an empty DecisionScope."""
    suite._section("4b. Proposal scope defaults")
    p = make_proposal()
    suite.must_pass(
        "defaults:proposal_scope_asset_ids",
        p.scope.asset_ids == [],
        "scope.asset_ids defaults to []",
        f"got {p.scope.asset_ids}",
    )


def test_proposal_assumptions_defaults_to_empty(suite: ConformanceSuite) -> None:
    """DecisionProposal.assumptions defaults to an empty list."""
    suite._section("4c. Proposal assumptions defaults")
    p = make_proposal()
    suite.must_pass(
        "defaults:proposal_assumptions",
        p.assumptions == [],
        "assumptions defaults to []",
        f"got {p.assumptions}",
    )


# ---------------------------------------------------------------------------
# 5. Posture defaults
# ---------------------------------------------------------------------------


def test_posture_history_defaults_to_empty(suite: ConformanceSuite) -> None:
    """UserPosture.history defaults to an empty tuple."""
    suite._section("5. Posture history defaults to empty tuple")
    posture = make_posture()
    suite.must_pass(
        "defaults:posture_history",
        posture.history == (),
        "history defaults to empty tuple",
        f"got {posture.history}",
    )


def test_posture_signature_optional(suite: ConformanceSuite) -> None:
    """UserPosture.posture_signature may be None (not yet signed)."""
    suite._section("5b. posture_signature optional")
    posture = make_posture(posture_signature=None)
    suite.must_pass(
        "defaults:posture_signature_optional",
        posture.posture_signature is None,
        "posture_signature=None accepted",
        f"got {posture.posture_signature}",
    )
