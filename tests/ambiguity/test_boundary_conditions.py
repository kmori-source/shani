"""
tests/ambiguity/test_boundary_conditions.py

Boundary condition tests for the Shani ambiguity escalation suite.

Covers T15 (Ambiguity Escalation) and related boundary cases:
- Blast radius at the exact allowed maximum
- Blast radius just above the allowed maximum
- minimum_evidence at exactly 0 and 1
- expires_at at minimum future offset
- target matching pattern boundary
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
from shani import BlastRadius
from shani.schemas.posture import PostureOutcome

from framework import ConformanceSuite
from ambiguity_fixtures import make_posture, make_proposal, evaluate_posture, future


# ---------------------------------------------------------------------------
# 1. Blast radius at the exact boundary
# ---------------------------------------------------------------------------


def test_blast_radius_at_exact_boundary(suite: ConformanceSuite) -> None:
    """Proposal with blast_radius == max_blast_radius must PASS."""
    suite._section("1a. Blast radius at exact boundary: PASS")
    posture = make_posture(max_blast_radius="limited")
    proposal = make_proposal(blast_radius=BlastRadius.LIMITED)
    outcome, refinement = evaluate_posture(proposal, posture)
    suite.must_pass(
        "boundary:blast_radius_exact",
        outcome == PostureOutcome.PASS,
        "blast_radius==max_blast_radius allows PASS",
        f"got {outcome}",
    )
    suite.must_pass(
        "boundary:no_refinement_on_pass",
        refinement is None,
        "no refinement request when outcome is PASS",
    )


def test_blast_radius_one_above_boundary(suite: ConformanceSuite) -> None:
    """Proposal with blast_radius one step above max_blast_radius must REJECT."""
    suite._section("1b. Blast radius one step above boundary: REJECT")
    posture = make_posture(max_blast_radius="limited")
    proposal = make_proposal(blast_radius=BlastRadius.SIGNIFICANT)
    outcome, refinement = evaluate_posture(proposal, posture)
    suite.must_fail(
        "boundary:blast_radius_exceeded",
        outcome == PostureOutcome.REJECT,
        "blast_radius > max_blast_radius → REJECT",
        f"got {outcome}",
    )
    suite.must_fail(
        "boundary:no_refinement_on_reject",
        refinement is None,
        "REJECT must not produce a refinement request",
    )


def test_blast_radius_critical_vs_limited(suite: ConformanceSuite) -> None:
    """Two steps above max must also be REJECT."""
    suite._section("1c. Blast radius CRITICAL vs max=limited: REJECT")
    posture = make_posture(max_blast_radius="limited")
    proposal = make_proposal(blast_radius=BlastRadius.CRITICAL)
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_fail(
        "boundary:blast_radius_critical_vs_limited",
        outcome == PostureOutcome.REJECT,
        "CRITICAL vs max=limited → REJECT",
        f"got {outcome}",
    )


# ---------------------------------------------------------------------------
# 2. Evidence count at exact boundary
# ---------------------------------------------------------------------------


def test_minimum_evidence_exactly_met(suite: ConformanceSuite) -> None:
    """Exactly minimum_evidence items must PASS."""
    suite._section("2a. minimum_evidence exactly met: PASS")
    from shani.schemas.decision import EvidenceItem

    posture = make_posture(minimum_evidence=2)
    proposal = make_proposal(
        evidence=[
            EvidenceItem(source="s1", content="ev1", confidence=0.9),
            EvidenceItem(source="s2", content="ev2", confidence=0.9),
        ]
    )
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_pass(
        "boundary:min_evidence_exact",
        outcome == PostureOutcome.PASS,
        "exactly minimum_evidence items → PASS",
        f"got {outcome}",
    )


def test_minimum_evidence_one_below(suite: ConformanceSuite) -> None:
    """One fewer than minimum_evidence must REJECT."""
    suite._section("2b. minimum_evidence one below: REJECT")
    from shani.schemas.decision import EvidenceItem

    posture = make_posture(minimum_evidence=2)
    proposal = make_proposal(
        evidence=[EvidenceItem(source="s1", content="ev1", confidence=0.9)],
    )
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_fail(
        "boundary:min_evidence_below",
        outcome == PostureOutcome.REJECT,
        "one below minimum_evidence → REJECT",
        f"got {outcome}",
    )


def test_minimum_evidence_zero_requirement(suite: ConformanceSuite) -> None:
    """minimum_evidence=0 must allow proposals with empty evidence."""
    suite._section("2c. minimum_evidence=0: PASS with zero items")
    posture = make_posture(minimum_evidence=0)
    proposal = make_proposal(evidence=[])
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_pass(
        "boundary:min_evidence_zero",
        outcome == PostureOutcome.PASS,
        "minimum_evidence=0 with empty evidence → PASS",
        f"got {outcome}",
    )


# ---------------------------------------------------------------------------
# 3. Target scope pattern at boundary
# ---------------------------------------------------------------------------


def test_target_exact_match_passes(suite: ConformanceSuite) -> None:
    """A target that exactly matches the pattern must PASS."""
    suite._section("3a. Target exactly matches pattern: PASS")
    posture = make_posture(target_scope=r"host:dev-01")
    proposal = make_proposal(target="host:dev-01")
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_pass(
        "boundary:target_exact_match",
        outcome == PostureOutcome.PASS,
        "exact target match → PASS",
        f"got {outcome}",
    )


def test_target_just_outside_pattern(suite: ConformanceSuite) -> None:
    """A target that does not match the pattern must REJECT."""
    suite._section("3b. Target outside pattern: REJECT")
    posture = make_posture(target_scope=r"host:dev-.*")
    proposal = make_proposal(target="host:prod-01")
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_fail(
        "boundary:target_outside_pattern",
        outcome == PostureOutcome.REJECT,
        "target outside pattern → REJECT",
        f"got {outcome}",
    )


def test_target_prefix_vs_full_match(suite: ConformanceSuite) -> None:
    """Pattern 'host:dev$' must not match 'host:development'."""
    suite._section("3c. Target prefix vs full match")
    posture = make_posture(target_scope=r"host:dev$")
    proposal_exact = make_proposal(target="host:dev")
    proposal_prefix = make_proposal(target="host:development")
    outcome_exact, _ = evaluate_posture(proposal_exact, posture)
    outcome_prefix, _ = evaluate_posture(proposal_prefix, posture)
    suite.must_pass(
        "boundary:anchored_exact",
        outcome_exact == PostureOutcome.PASS,
        "anchored pattern matches exact target",
        f"got {outcome_exact}",
    )
    suite.must_fail(
        "boundary:anchored_prefix_rejected",
        outcome_prefix == PostureOutcome.REJECT,
        "anchored pattern rejects extended target",
        f"got {outcome_prefix}",
    )


# ---------------------------------------------------------------------------
# 4. Confidence at extremes
# ---------------------------------------------------------------------------


def test_confidence_zero(suite: ConformanceSuite) -> None:
    """confidence=0.0 is valid at the schema level."""
    suite._section("4a. confidence=0.0")
    proposal = make_proposal(confidence=0.0)
    suite.must_pass(
        "boundary:confidence_zero",
        proposal.confidence == 0.0,
        "confidence=0.0 accepted by schema",
    )


def test_confidence_one(suite: ConformanceSuite) -> None:
    """confidence=1.0 is valid."""
    suite._section("4b. confidence=1.0")
    proposal = make_proposal(confidence=1.0)
    suite.must_pass(
        "boundary:confidence_one",
        proposal.confidence == 1.0,
        "confidence=1.0 accepted by schema",
    )


# ---------------------------------------------------------------------------
# 5. expires_at boundary
# ---------------------------------------------------------------------------


def test_expires_at_minimum_future(suite: ConformanceSuite) -> None:
    """expires_at just 1 second in the future must be valid."""
    suite._section("5. expires_at minimum future offset")
    proposal = make_proposal(expires_at=future(seconds=1))
    suite.must_pass(
        "boundary:expires_at_min_future",
        proposal.expires_at is not None,
        "expires_at 1s in future is valid",
    )
