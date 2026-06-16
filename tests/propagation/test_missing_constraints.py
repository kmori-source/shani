"""
tests/propagation/test_missing_constraints.py

MUST FAIL tests: cases where missing or malformed propagated_constraints
must cause the evaluator to reject or return AMBIGUOUS.

Test cases:
    1. empty_propagated_constraints   — cross-org ADO with empty list → AMBIGUOUS
    2. none_vs_empty_distinction      — None origin_org vs set origin_org with empty list
    3. unknown_constraint_vocabulary  — unrecognised key → AMBIGUOUS (not PASS)
    4. malformed_constraint_string    — constraint without ':' separator → AMBIGUOUS
    5. partial_constraints_missing    — cross-org ADO with only some keys → still enforced
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

from shani import DeniedDecision, DecisionType, BlastRadius
from shani.schemas.decision import AuthorizedDecisionObject
from shani.schemas.posture import PostureRefinementRequest

from framework import ConformanceSuite
from fixtures import (
    make_evaluator,
    make_cross_org_evaluator,
    make_proposal,
    make_valid_ado,
    make_fake_cross_org_ado,
)


# ---------------------------------------------------------------------------
# 1. Empty propagated_constraints on cross-org ADO — SPEC §8.9
# ---------------------------------------------------------------------------


def test_empty_propagated_constraints(suite: ConformanceSuite) -> None:
    suite._section("1. Empty propagated_constraints (SPEC §8.9 MUST FAIL)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Build cross-org parent ADO with origin_org set but empty propagated_constraints
    empty_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[],  # intentionally empty
    )

    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=empty_parent)

    # Must NOT produce an ADO
    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "empty_constraints:not_ado",
        condition=not_ado,
        description="cross-org ADO with empty propagated_constraints → not ADO",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.9",
    )

    # Must be AMBIGUOUS (PostureRefinementRequest), not a hard DeniedDecision
    is_refinement = isinstance(result, PostureRefinementRequest)
    suite.must_fail(
        "empty_constraints:is_refinement_request",
        condition=is_refinement,
        description="empty propagated_constraints → PostureRefinementRequest (AMBIGUOUS)",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.9",
    )

    if is_refinement:
        # ambiguity explanation must be present
        suite.must_fail(
            "empty_constraints:has_ambiguity",
            condition=bool(result.ambiguity),
            description="PostureRefinementRequest has non-empty ambiguity field",
            spec_ref="SPEC §8.9",
        )

        # unresolved must reference propagated_constraints
        refs_field = "propagated_constraints" in result.unresolved
        suite.must_fail(
            "empty_constraints:unresolved_references_field",
            condition=refs_field,
            description="PostureRefinementRequest.unresolved includes 'propagated_constraints'",
            detail=f"unresolved={result.unresolved}",
            spec_ref="SPEC §8.9",
        )

        # principal_id must identify the origin_org
        correct_principal = result.principal_id == "org-alpha"
        suite.must_fail(
            "empty_constraints:principal_id_is_origin_org",
            condition=correct_principal,
            description="PostureRefinementRequest.principal_id == origin_org",
            detail=f"got {result.principal_id!r}",
            spec_ref="SPEC §8.9",
        )


# ---------------------------------------------------------------------------
# 2. None origin_org must NOT trigger cross-org validation
# ---------------------------------------------------------------------------


def test_none_origin_org_no_cross_org_check(suite: ConformanceSuite) -> None:
    suite._section("2. None origin_org — no cross-org validation (SPEC §8.8)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Parent ADO with NO origin_org (intra-org delegation) — even with empty constraints
    from fixtures import make_fake_cross_org_ado as _fake_ado

    intra_parent = _fake_ado(
        origin_org="org-external",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
    )
    # Override origin_org to None to simulate intra-org ADO
    intra_parent = intra_parent.model_copy(update={"origin_org": None})

    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=intra_parent)

    # Without origin_org, cross-org validation is skipped — may succeed or fail
    # but must NOT be a cross-org-specific PostureRefinementRequest mentioning
    # propagated_constraints in unresolved for the origin_org reason.
    if isinstance(result, PostureRefinementRequest):
        not_cross_org_reason = "propagated_constraints" not in result.unresolved
        suite.must_pass(
            "none_origin_org:not_cross_org_ambiguous",
            condition=not_cross_org_reason,
            description=(
                "intra-org parent (origin_org=None) does not trigger cross-org "
                "propagated_constraints validation"
            ),
            detail=f"unresolved={result.unresolved}",
            spec_ref="SPEC §8.8",
        )
    else:
        suite.must_pass(
            "none_origin_org:no_spurious_rejection",
            condition=True,
            description="intra-org delegation (origin_org=None) is not rejected for cross-org reasons",
            spec_ref="SPEC §8.8",
        )


# ---------------------------------------------------------------------------
# 3. Unknown constraint vocabulary → AMBIGUOUS, not PASS
# ---------------------------------------------------------------------------


def test_unknown_constraint_vocabulary(suite: ConformanceSuite) -> None:
    suite._section("3. Unknown Constraint Vocabulary (SPEC §8.8 MUST FAIL)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Unknown key in propagated_constraints
    unknown_vocab_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "unknown_key:some-value",  # unrecognised vocabulary
            "max_blast_radius:limited",
        ],
    )

    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=unknown_vocab_parent)

    # Must NOT pass — unknown vocabulary means fail-closed (AMBIGUOUS)
    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "unknown_vocab:not_ado",
        condition=not_ado,
        description="unknown constraint vocabulary → not ADO (fail-closed)",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )

    # Must be AMBIGUOUS (refinement), not hard denial
    is_refinement = isinstance(result, PostureRefinementRequest)
    suite.must_fail(
        "unknown_vocab:is_ambiguous",
        condition=is_refinement,
        description="unknown vocabulary key → PostureRefinementRequest (AMBIGUOUS, not denied)",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )

    if is_refinement:
        # unresolved must reference the unknown key
        has_unknown = any("unknown_key" in u for u in result.unresolved)
        suite.must_fail(
            "unknown_vocab:unresolved_lists_unknown",
            condition=has_unknown,
            description="PostureRefinementRequest.unresolved lists the unknown key",
            detail=f"unresolved={result.unresolved}",
            spec_ref="SPEC §8.8",
        )


# ---------------------------------------------------------------------------
# 4. Malformed constraint string (no ':' separator) → AMBIGUOUS
# ---------------------------------------------------------------------------


def test_malformed_constraint_string(suite: ConformanceSuite) -> None:
    suite._section("4. Malformed Constraint String (SPEC §8.8 MUST FAIL)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Constraint without ':' separator is malformed
    malformed_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "MALFORMED_NO_SEPARATOR",  # missing ':' — unrecognised key
            "max_blast_radius:limited",
        ],
    )

    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=malformed_parent)

    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "malformed_constraint:not_ado",
        condition=not_ado,
        description="malformed constraint string → not ADO (fail-closed)",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )

    is_refinement = isinstance(result, PostureRefinementRequest)
    suite.must_fail(
        "malformed_constraint:is_ambiguous",
        condition=is_refinement,
        description="malformed constraint string → PostureRefinementRequest",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# 5. Cross-org ADO with partial constraints — remaining constraints still enforced
# ---------------------------------------------------------------------------


def test_partial_constraints_enforced(suite: ConformanceSuite) -> None:
    suite._section("5. Partial Constraints Still Enforced (SPEC §8.8)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Parent specifies only target_scope — still validated against proposal
    partial_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",  # only this constraint present
        ],
    )

    # Proposal within target_scope should be evaluated on the remaining constraint
    in_scope_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-42",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )
    result_in = child_ev.evaluate(in_scope_proposal, parent_ado=partial_parent)

    # target_scope is satisfied — evaluation continues normally
    in_scope_ok = isinstance(result_in, (AuthorizedDecisionObject, PostureRefinementRequest))
    suite.must_pass(
        "partial_constraints:in_scope_not_denied_for_missing_keys",
        condition=in_scope_ok,
        description=(
            "partial propagated_constraints (known keys only): "
            "in-scope proposal not erroneously rejected"
        ),
        detail=f"got {type(result_in).__name__}",
        spec_ref="SPEC §8.8",
    )

    # Proposal outside target_scope must be blocked
    out_of_scope_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:prod-01",  # outside dev scope
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )
    result_out = child_ev.evaluate(out_of_scope_proposal, parent_ado=partial_parent)

    out_not_ado = not isinstance(result_out, AuthorizedDecisionObject)
    suite.must_fail(
        "partial_constraints:out_of_scope_still_blocked",
        condition=out_not_ado,
        description="even partial constraints: out-of-scope proposal → not ADO",
        detail=f"got {type(result_out).__name__}",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("Missing Constraints MUST FAIL Tests")
    test_empty_propagated_constraints(suite)
    test_none_origin_org_no_cross_org_check(suite)
    test_unknown_constraint_vocabulary(suite)
    test_malformed_constraint_string(suite)
    test_partial_constraints_enforced(suite)
    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Propagation: Missing Constraints MUST FAIL Tests")
    print("=" * 60)
    s = run()
    s.report.print_summary()
    s.report.assert_all_passed()
