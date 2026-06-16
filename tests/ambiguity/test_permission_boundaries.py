"""
tests/ambiguity/test_permission_boundaries.py

Tests for permission boundary interpretation.

Verifies that permission decisions are consistent and deterministic at the
boundary between allowed and denied:
- Reversibility requirement at the exact boundary
- OrgPolicy absolute constraints override posture
- PostureEngine REJECT is always deterministic (not AMBIGUOUS) for structural violations
- Repeated AMBIGUOUS evaluations of the same proposal are consistent
- Agent decision_type whitelist boundary
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
from datetime import datetime, timezone

from shani import BlastRadius, DecisionType, DeniedDecision
from shani.schemas.posture import PostureOutcome, PostureConstraints, UserPosture
from shani.posture.engine import PostureEngine

from framework import ConformanceSuite
from ambiguity_fixtures import (
    make_evaluator,
    make_posture,
    make_proposal,
    evaluate_posture,
)


# ---------------------------------------------------------------------------
# 1. Reversibility at the exact boundary
# ---------------------------------------------------------------------------


def test_reversibility_required_true_blocks_irreversible(suite: ConformanceSuite) -> None:
    """reversibility_required=True must REJECT an irreversible proposal."""
    suite._section("1a. reversibility_required=True blocks irreversible")
    posture = make_posture(reversibility_required=True)
    proposal = make_proposal(reversibility=False)
    outcome, refinement = evaluate_posture(proposal, posture)
    suite.must_fail(
        "perm:reversibility_blocks_irreversible",
        outcome == PostureOutcome.REJECT,
        "irreversible proposal REJECTED when reversibility_required=True",
        f"got {outcome}",
    )
    suite.must_fail(
        "perm:reversibility_no_refinement",
        refinement is None,
        "REJECT does not produce refinement",
    )


def test_reversibility_required_false_allows_irreversible(suite: ConformanceSuite) -> None:
    """reversibility_required=False must allow an irreversible proposal through posture."""
    suite._section("1b. reversibility_required=False allows irreversible")
    posture = make_posture(reversibility_required=False)
    proposal = make_proposal(reversibility=False)
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_pass(
        "perm:reversibility_false_allows",
        outcome == PostureOutcome.PASS,
        "irreversible proposal PASSES posture when reversibility_required=False",
        f"got {outcome}",
    )


def test_reversibility_required_true_allows_reversible(suite: ConformanceSuite) -> None:
    """reversibility_required=True must still PASS reversible proposals."""
    suite._section("1c. reversibility_required=True allows reversible")
    posture = make_posture(reversibility_required=True)
    proposal = make_proposal(reversibility=True)
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_pass(
        "perm:reversibility_true_allows_reversible",
        outcome == PostureOutcome.PASS,
        "reversible proposal PASSES when reversibility_required=True",
        f"got {outcome}",
    )


# ---------------------------------------------------------------------------
# 2. Agent granted_dsal at the exact boundary
# ---------------------------------------------------------------------------


def test_unregistered_agent_denied(suite: ConformanceSuite) -> None:
    """An unregistered agent must be denied."""
    suite._section("2. Unregistered agent denied")
    ev = make_evaluator()
    proposal = make_proposal(proposed_by="agent/not-registered")
    result = ev.evaluate(proposal)
    suite.must_fail(
        "perm:unregistered_agent_denied",
        isinstance(result, DeniedDecision),
        "unregistered agent results in DeniedDecision",
        f"got {type(result).__name__}",
    )


# ---------------------------------------------------------------------------
# 3. OrgPolicy absolute constraints override posture
# ---------------------------------------------------------------------------


def test_org_policy_tighter_than_posture_rejects(suite: ConformanceSuite) -> None:
    """When OrgPolicy is tighter than UserPosture, the posture must be rejected."""
    suite._section("3. OrgPolicy absolute constraints override posture")
    from shani.authority.policy import OrgPolicy, OrgPolicyAbsoluteConstraints

    posture = make_posture(max_blast_radius="critical")
    org_policy = OrgPolicy(
        absolute_constraints=OrgPolicyAbsoluteConstraints(
            max_blast_radius="limited",
        )
    )
    engine = PostureEngine(user_posture=posture, org_policy=org_policy)
    proposal = make_proposal(blast_radius=BlastRadius.CRITICAL)
    outcome, _ = engine.evaluate(proposal)
    suite.must_fail(
        "perm:org_policy_overrides_posture",
        outcome == PostureOutcome.REJECT,
        "OrgPolicy max=limited overrides posture max=critical → REJECT",
        f"got {outcome}",
    )


# ---------------------------------------------------------------------------
# 4. Structural violations always produce REJECT (not AMBIGUOUS)
# ---------------------------------------------------------------------------


def test_structural_violation_always_reject(suite: ConformanceSuite) -> None:
    """Structural constraint violations must always produce REJECT, never AMBIGUOUS."""
    suite._section("4. Structural violation → REJECT (not AMBIGUOUS)")
    posture = make_posture(
        target_scope=r"host:dev-.*",
        max_blast_radius="limited",
        reversibility_required=True,
        minimum_evidence=1,
    )
    violations = [
        ("target_out_of_scope", make_proposal(target="host:prod-01")),
        ("blast_radius_exceeded", make_proposal(blast_radius=BlastRadius.CRITICAL)),
        ("reversibility_violated", make_proposal(reversibility=False)),
        ("evidence_below_minimum", make_proposal(evidence=[])),
    ]
    for name, proposal in violations:
        outcome, _ = evaluate_posture(proposal, posture)
        suite.must_fail(
            f"perm:structural_{name}",
            outcome == PostureOutcome.REJECT,
            f"{name} → REJECT (not AMBIGUOUS)",
            f"got {outcome}",
        )


# ---------------------------------------------------------------------------
# 5. Repeated AMBIGUOUS evaluations are consistent
# ---------------------------------------------------------------------------


def test_repeated_ambiguous_requests_consistent(suite: ConformanceSuite) -> None:
    """Repeated AMBIGUOUS evaluations of the same proposal must return consistent results."""
    suite._section("5. Repeated AMBIGUOUS requests are consistent")
    posture_unknown_br = UserPosture(
        version="1.0",
        principal_id="tester@example.com",
        signed_at=datetime.now(tz=timezone.utc),
        intent_statement="Ambiguity test.",
        simulation_ref="sim-001",
        constraints=PostureConstraints(
            target_scope=r"host:dev-.*",
            max_blast_radius="unknown_value",
            reversibility_required=True,
            minimum_evidence=1,
        ),
        posture_signature="test-sig",
    )
    proposal = make_proposal()

    outcomes = []
    unresolved_sets = []
    for _ in range(5):
        engine = PostureEngine(user_posture=posture_unknown_br)
        outcome, refinement = engine.evaluate(proposal)
        outcomes.append(outcome)
        if refinement is not None:
            unresolved_sets.append(frozenset(refinement.unresolved))

    suite.must_pass(
        "perm:repeated_ambiguous_consistent_outcome",
        len(set(outcomes)) == 1,
        "all repeated evaluations produce the same outcome",
        f"outcomes varied: {outcomes}",
    )
    if unresolved_sets:
        suite.must_pass(
            "perm:repeated_ambiguous_consistent_unresolved",
            len(set(unresolved_sets)) == 1,
            "all repeated refinements list the same unresolved constraints",
            f"unresolved varied: {unresolved_sets}",
        )


# ---------------------------------------------------------------------------
# 6. Delegation decision type whitelist boundary
# ---------------------------------------------------------------------------


def test_agent_disallowed_decision_type_denied(suite: ConformanceSuite) -> None:
    """Agent proposing a disallowed decision_type must be denied."""
    suite._section("6. Agent allowed_decision_types: disallowed type")
    ev = make_evaluator()
    # agent/low is only allowed 'remediation'
    proposal = make_proposal(
        proposed_by="agent/low",
        decision_type=DecisionType.POLICY_UPDATE,
    )
    result = ev.evaluate(proposal)
    suite.must_fail(
        "perm:disallowed_decision_type",
        isinstance(result, DeniedDecision),
        "disallowed decision_type results in DeniedDecision",
        f"got {type(result).__name__}",
    )
