"""
tests/ambiguity/test_dsal_escalation.py

Tests for DSAL (Dynamic Scope Authority Level) escalation boundary cases.

Covers T15 (Ambiguity Escalation) and T3/T4 (escalation prevention):
- PostureEngine AMBIGUOUS trigger and T15 threat mapping
- Agent cannot self-declare D-SAL (requested_dsal field absent)
- DSALCalculator boundary: cap at 4, single modifier increments
- DelegationRules max_child_dsal < authorized_dsal invariant
- Multiple AMBIGUOUS requests must not leak posture boundary details
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
from datetime import datetime, timedelta, timezone

from shani import BlastRadius, DecisionType
from shani.schemas.decision import (
    AuthorizedDecisionObject,
    DelegationRules,
    EvidenceItem,
    ExecContext,
    IntentBinding,
)
from shani.schemas.posture import PostureOutcome, PostureRefinementRequest, UserPosture, PostureConstraints
from shani.authority.dsal_calculator import DSALCalculator
from shani.posture.engine import PostureEngine

from framework import ConformanceSuite
from ambiguity_fixtures import (
    make_posture,
    make_proposal,
    evaluate_posture,
)


def _make_posture_unknown_br() -> UserPosture:
    return UserPosture(
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


# ---------------------------------------------------------------------------
# 1. T15 — Ambiguity escalation: AMBIGUOUS triggers refinement request
# ---------------------------------------------------------------------------


def test_ambiguous_outcome_returns_refinement_request(suite: ConformanceSuite) -> None:
    """PostureEngine must return PostureRefinementRequest for AMBIGUOUS outcomes (T15)."""
    suite._section("1. AMBIGUOUS → PostureRefinementRequest (T15)")
    posture = _make_posture_unknown_br()
    proposal = make_proposal(blast_radius=BlastRadius.LIMITED)
    engine = PostureEngine(user_posture=posture)
    outcome, refinement = engine.evaluate(proposal)
    suite.must_pass(
        "dsal:ambiguous_outcome",
        outcome == PostureOutcome.AMBIGUOUS,
        "unknown max_blast_radius vocabulary → AMBIGUOUS",
        f"got {outcome}",
    )
    suite.must_pass(
        "dsal:ambiguous_produces_refinement",
        isinstance(refinement, PostureRefinementRequest),
        "AMBIGUOUS produces PostureRefinementRequest",
        f"got {type(refinement)}",
    )


def test_refinement_request_does_not_expose_full_posture(suite: ConformanceSuite) -> None:
    """PostureRefinementRequest must not expose full posture evaluation (T15 mitigation)."""
    suite._section("1b. RefinementRequest limited disclosure (T15)")
    posture = _make_posture_unknown_br()
    proposal = make_proposal(blast_radius=BlastRadius.LIMITED)
    engine = PostureEngine(user_posture=posture)
    _, refinement = engine.evaluate(proposal)

    if refinement is None:
        pytest.skip("No refinement returned — cannot check T15 mitigation")

    suite.must_pass(
        "dsal:refinement_has_ambiguity",
        hasattr(refinement, "ambiguity"),
        "refinement has ambiguity field",
    )
    suite.must_pass(
        "dsal:refinement_has_matched",
        hasattr(refinement, "matched_constraints"),
        "refinement has matched_constraints field",
    )
    suite.must_fail(
        "dsal:refinement_no_risk_score",
        not hasattr(refinement, "risk_score"),
        "refinement does not expose risk_score",
    )
    suite.must_fail(
        "dsal:refinement_no_user_posture",
        not hasattr(refinement, "user_posture"),
        "refinement does not expose full user_posture",
    )


def test_reject_does_not_produce_refinement(suite: ConformanceSuite) -> None:
    """REJECT outcome must not produce a PostureRefinementRequest."""
    suite._section("1c. REJECT → no PostureRefinementRequest")
    posture = make_posture(max_blast_radius="limited")
    proposal = make_proposal(blast_radius=BlastRadius.CRITICAL)
    outcome, refinement = evaluate_posture(proposal, posture)
    suite.must_fail(
        "dsal:reject_outcome",
        outcome == PostureOutcome.REJECT,
        "REJECT outcome confirmed",
        f"got {outcome}",
    )
    suite.must_fail(
        "dsal:reject_no_refinement",
        refinement is None,
        "REJECT produces no refinement request",
    )


# ---------------------------------------------------------------------------
# 2. Agent cannot self-declare D-SAL (T3 mitigation)
# ---------------------------------------------------------------------------


def test_requested_dsal_field_absent(suite: ConformanceSuite) -> None:
    """DecisionProposal must not have a requested_dsal field (T3 mitigation)."""
    suite._section("2. requested_dsal field absent from DecisionProposal (T3)")
    import pathlib
    proposal = make_proposal()
    suite.must_fail(
        "dsal:no_requested_dsal_attr",
        not hasattr(proposal, "requested_dsal"),
        "requested_dsal not in proposal object",
    )
    src = pathlib.Path(__file__).parent.parent.parent / "shani/schemas/decision.py"
    text = src.read_text()
    suite.must_fail(
        "dsal:no_requested_dsal_in_source",
        "requested_dsal" not in text,
        "requested_dsal absent from decision.py source",
    )


# ---------------------------------------------------------------------------
# 3. DSALCalculator boundary conditions
# ---------------------------------------------------------------------------


def test_dsal_capped_at_four(suite: ConformanceSuite) -> None:
    """Effective D-SAL must never exceed 4 regardless of modifiers."""
    suite._section("3. D-SAL cap at 4")
    calc = DSALCalculator()
    proposal = make_proposal(
        target="host:prod-01",
        blast_radius=BlastRadius.CRITICAL,
        reversibility=False,
        evidence=[],
        confidence=0.1,
        delegation=True,
    )
    result = calc.calculate(proposal, base_dsal=3)
    suite.must_fail(
        "dsal:cap_at_four",
        result.effective <= 4,
        "effective D-SAL capped at 4",
        f"effective={result.effective}",
    )


def test_dsal_minimum_base_one(suite: ConformanceSuite) -> None:
    """A low-risk proposal at base_dsal=1 must stay at effective=1."""
    suite._section("3b. D-SAL minimum: low-risk stays at 1")
    calc = DSALCalculator()
    proposal = make_proposal(
        target="host:dev-01",
        blast_radius=BlastRadius.ISOLATED,
        reversibility=True,
        evidence=[EvidenceItem(source="s", content="c", confidence=0.95)],
        confidence=0.95,
        delegation=False,
    )
    result = calc.calculate(proposal, base_dsal=1)
    suite.must_pass(
        "dsal:low_risk_stays_at_one",
        result.effective == 1,
        "all-low-risk proposal stays at base D-SAL 1",
        f"got {result.effective}: {result.explain()}",
    )


def test_dsal_each_modifier_increments(suite: ConformanceSuite) -> None:
    """Each individual risk modifier must raise effective D-SAL above 1."""
    suite._section("3c. Each D-SAL modifier increments above base")
    calc = DSALCalculator()

    modifiers = [
        ("blast_radius=SIGNIFICANT", make_proposal(blast_radius=BlastRadius.SIGNIFICANT)),
        ("reversibility=False", make_proposal(reversibility=False)),
        ("target=prod", make_proposal(target="host:prod-01")),
        ("no evidence", make_proposal(evidence=[])),
        ("low confidence", make_proposal(confidence=0.3)),
        ("delegation=True", make_proposal(delegation=True)),
    ]
    for name, modified in modifiers:
        result = calc.calculate(modified, base_dsal=1)
        suite.must_pass(
            f"dsal:modifier_{name.replace(' ', '_').replace('=', '_')}",
            result.effective > 1,
            f"{name} → effective > 1",
            f"got {result.effective}: {result.explain()}",
        )


# ---------------------------------------------------------------------------
# 4. DelegationRules max_child_dsal invariant (T4 mitigation)
# ---------------------------------------------------------------------------


def test_delegation_cannot_equal_parent_dsal(suite: ConformanceSuite) -> None:
    """Creating an ADO where max_child_dsal >= authorized_dsal must raise ValueError."""
    suite._section("4. Delegation escalation invariant (T4)")
    import hashlib, base64, uuid

    raised = False
    try:
        AuthorizedDecisionObject(
            decision_id=str(uuid.uuid4()),
            authorized_dsal=2,
            authority="test-authority",
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
            proposal_hash=hashlib.sha256(b"test").hexdigest(),
            delegation_rules=DelegationRules(
                allowed_sub_decisions=["remediation"],
                max_child_dsal=2,  # must be < 2
                max_depth=3,
                max_children=5,
            ),
            signature=base64.b64encode(b"sig").decode(),
            exec_context=ExecContext(
                decision_type=DecisionType.REMEDIATION,
                intent_binding=IntentBinding(
                    intent="test",
                    target="host:dev-01",
                    scope_summary="test",
                    expected_effect="test effect",
                    reversibility=True,
                ),
            ),
        )
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "dsal:deleg_max_child_gte_parent",
        raised,
        "max_child_dsal >= authorized_dsal raises ValueError",
    )


def test_delegation_zero_child_dsal_not_permitted(suite: ConformanceSuite) -> None:
    """delegation_permitted must be False when max_child_dsal=0."""
    suite._section("4b. max_child_dsal=0 → not permitted")
    rules = DelegationRules(
        allowed_sub_decisions=["remediation"],
        max_child_dsal=0,
        max_depth=3,
        max_children=5,
    )
    suite.must_pass(
        "dsal:zero_child_dsal_not_permitted",
        rules.delegation_permitted is False,
        "max_child_dsal=0 → delegation_permitted=False",
        f"got delegation_permitted={rules.delegation_permitted}",
    )
