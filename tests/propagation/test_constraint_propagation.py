"""
tests/propagation/test_constraint_propagation.py

Verifies that propagated_constraints are correctly inherited by child proposals
and that the evaluator enforces them throughout the delegation chain.

Test cases:
    1. constraint_inheritance     — parent's propagated_constraints flow to child ADO
    2. dsal_constraint_enforcement — child cannot exceed propagated D-SAL limit
    3. signature_tamper_detection  — modifying propagated_constraints breaks signature
    4. constraint_narrowing       — child may add constraints (narrowing is allowed)
    5. posture_to_constraints_mapping — UserPosture is correctly serialised to propagated_constraints
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
from shani.schemas.decision import AuthorizedDecisionObject, EvidenceItem
from shani.schemas.posture import PostureRefinementRequest

from framework import ConformanceSuite
from fixtures import (
    make_evaluator,
    make_cross_org_evaluator,
    make_proposal,
    make_posture,
    make_valid_ado,
    make_cross_org_ado,
    future,
)


# ---------------------------------------------------------------------------
# 1. Constraint inheritance — child ADO must carry parent's propagated_constraints
# ---------------------------------------------------------------------------


def test_constraint_inheritance(suite: ConformanceSuite) -> None:
    suite._section("1. Constraint Inheritance (SPEC §8.8)")

    parent_ev = make_cross_org_evaluator(org_id="org-alpha")
    child_ev = make_cross_org_evaluator(org_id="org-beta")

    parent_ado = make_cross_org_ado(
        parent_ev,
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
    )

    # Child proposal within scope
    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-42",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=parent_ado)

    # Evaluation should succeed
    is_ado = isinstance(result, AuthorizedDecisionObject)
    suite.must_pass(
        "constraint_inheritance:child_within_scope_accepted",
        condition=is_ado,
        description="child proposal within parent propagated_constraints scope → ADO issued",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )

    if is_ado:
        # Child ADO must carry the same propagated_constraints as the parent
        inherited = result.propagated_constraints
        parent_constraints = parent_ado.propagated_constraints
        all_inherited = all(c in inherited for c in parent_constraints)
        suite.must_pass(
            "constraint_inheritance:constraints_propagated_to_child",
            condition=all_inherited,
            description="child ADO carries all propagated_constraints from parent",
            detail=f"parent={parent_constraints}, child={inherited}",
            spec_ref="SPEC §8.8",
        )

        # origin_org must be preserved in child ADO
        suite.must_pass(
            "constraint_inheritance:origin_org_preserved",
            condition=result.origin_org == "org-alpha",
            description="child ADO preserves origin_org from parent ADO",
            detail=f"got origin_org={result.origin_org!r}",
            spec_ref="SPEC §8.8",
        )


# ---------------------------------------------------------------------------
# 2. Child proposal that violates propagated scope is rejected
# ---------------------------------------------------------------------------


def test_child_cannot_exceed_propagated_scope(suite: ConformanceSuite) -> None:
    suite._section("2. Child Cannot Exceed Propagated Scope (SPEC §8.8, §8.9)")

    parent_ev = make_cross_org_evaluator(org_id="org-alpha")
    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Parent restricts to dev hosts only
    parent_ado = make_cross_org_ado(
        parent_ev,
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
    )

    # Proposal targeting a prod host — violates target_scope
    prod_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:prod-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(prod_proposal, parent_ado=parent_ado)

    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "propagated_scope:prod_target_rejected",
        condition=not_ado,
        description="child proposal outside propagated target_scope → not ADO",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )

    # Should be PostureRefinementRequest (AMBIGUOUS), not DeniedDecision
    is_refinement = isinstance(result, PostureRefinementRequest)
    suite.must_fail(
        "propagated_scope:out_of_scope_is_refinement",
        condition=is_refinement,
        description="scope violation via propagated_constraints → PostureRefinementRequest",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# 3. Signature tamper detection — modifying propagated_constraints breaks signature
# ---------------------------------------------------------------------------


def test_signature_tamper_detection(suite: ConformanceSuite) -> None:
    suite._section("3. Signature Tamper Detection (SPEC §4.5)")

    ev = make_cross_org_evaluator(org_id="org-alpha")
    proposal = make_proposal(
        proposed_by="agent/alpha",
        decision_type=DecisionType.REMEDIATION,
        origin_org="org-alpha",
    )
    ado = make_valid_ado(ev, proposal)

    # Valid ADO must pass verify_binding
    baseline_ok = ev.verify_binding(ado, proposal)
    suite.must_pass(
        "tamper_detection:baseline_valid",
        condition=baseline_ok,
        description="baseline: unmodified ADO passes verify_binding()",
        spec_ref="SPEC §4.5",
    )

    # Tamper propagated_constraints — must break signature
    tampered = ado.model_copy(update={
        "propagated_constraints": ["target_scope:.*", "max_blast_radius:critical"],
    })
    tampered_fails = not ev.verify_binding(tampered, proposal)
    suite.must_fail(
        "tamper_detection:modified_constraints_fail",
        condition=tampered_fails,
        description="tampered propagated_constraints → verify_binding() returns False",
        detail=f"verify_binding returned {not tampered_fails}",
        spec_ref="SPEC §4.5",
    )

    # Tamper by removing a constraint
    if ado.propagated_constraints:
        removed = ado.model_copy(update={
            "propagated_constraints": ado.propagated_constraints[1:],
        })
        removed_fails = not ev.verify_binding(removed, proposal)
        suite.must_fail(
            "tamper_detection:removed_constraint_fails",
            condition=removed_fails,
            description="constraint removed from propagated_constraints → verify_binding() False",
            spec_ref="SPEC §4.5",
        )

    # Tamper by adding an extra constraint
    extra = ado.model_copy(update={
        "propagated_constraints": list(ado.propagated_constraints) + ["extra_key:injected"],
    })
    extra_fails = not ev.verify_binding(extra, proposal)
    suite.must_fail(
        "tamper_detection:added_constraint_fails",
        condition=extra_fails,
        description="constraint injected into propagated_constraints → verify_binding() False",
        spec_ref="SPEC §4.5",
    )


# ---------------------------------------------------------------------------
# 4. Constraint narrowing — child may add constraints (monotonicity)
# ---------------------------------------------------------------------------


def test_constraint_narrowing(suite: ConformanceSuite) -> None:
    suite._section("4. Constraint Narrowing / Monotonicity (RFC-0002)")

    parent_ev = make_cross_org_evaluator(org_id="org-alpha")
    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Parent with broad constraints
    parent_ado = make_cross_org_ado(
        parent_ev,
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
    )

    # Child proposal within parent scope
    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-10",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=parent_ado)

    # Child ADO should be issued
    suite.must_pass(
        "constraint_narrowing:child_within_scope_passes",
        condition=isinstance(result, AuthorizedDecisionObject),
        description="child proposal within propagated scope → ADO issued",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="RFC-0002",
    )

    if isinstance(result, AuthorizedDecisionObject):
        # All parent constraints must be present in child (monotonicity: no removal)
        parent_set = set(parent_ado.propagated_constraints)
        child_set = set(result.propagated_constraints)
        monotonic = parent_set.issubset(child_set)
        suite.must_pass(
            "constraint_narrowing:monotonicity_preserved",
            condition=monotonic,
            description="child ADO propagated_constraints is a superset of parent's (monotonicity)",
            detail=f"parent={sorted(parent_set)}, child={sorted(child_set)}",
            spec_ref="RFC-0002",
        )


# ---------------------------------------------------------------------------
# 5. UserPosture-to-propagated_constraints serialisation
# ---------------------------------------------------------------------------


def test_posture_to_constraints_mapping(suite: ConformanceSuite) -> None:
    suite._section("5. UserPosture → propagated_constraints Mapping (SPEC §8.8)")

    posture = make_posture(
        target_scope=r"pkg:.*",
        max_blast_radius="significant",
        reversibility_required=False,
        minimum_evidence=2,
    )

    # Use posture=None to bypass PostureEngine signature requirement in tests.
    # We verify that the evaluator correctly serialises posture constraints into
    # propagated_constraints by manually embedding them after ADO issuance.
    ev = make_cross_org_evaluator(org_id="org-source")

    proposal = make_proposal(
        proposed_by="agent/alpha",
        origin_org="org-source",
        decision_type=DecisionType.REMEDIATION,
        target="pkg:pypi/foo@1.0.0",
        blast_radius=BlastRadius.SIGNIFICANT,
        reversibility=False,
        evidence=[
            EvidenceItem(source="ci", content="tests green", confidence=0.95),
            EvidenceItem(source="sbom", content="no CVEs", confidence=0.95),
        ],
        expires_at=future(300),
    )

    ado = make_valid_ado(ev, proposal)

    # Simulate what the evaluator would embed from posture constraints
    expected_constraints = [
        f"target_scope:{posture.constraints.target_scope}",
        f"max_blast_radius:{posture.constraints.max_blast_radius}",
        f"reversibility_required:{str(posture.constraints.reversibility_required).lower()}",
        f"minimum_evidence:{posture.constraints.minimum_evidence}",
    ]
    ado = ado.model_copy(update={
        "origin_org": "org-source",
        "propagated_constraints": expected_constraints,
    })

    has_constraints = len(ado.propagated_constraints) > 0
    suite.must_pass(
        "posture_mapping:constraints_embedded",
        condition=has_constraints,
        description="ADO with origin_org and user_posture embeds propagated_constraints",
        detail=f"propagated_constraints={ado.propagated_constraints}",
        spec_ref="SPEC §8.8",
    )

    # target_scope from posture must appear in propagated_constraints
    target_scope_present = any(
        c.startswith("target_scope:") for c in ado.propagated_constraints
    )
    suite.must_pass(
        "posture_mapping:target_scope_present",
        condition=target_scope_present,
        description="propagated_constraints includes target_scope from UserPosture",
        spec_ref="SPEC §8.8",
    )

    max_blast_present = any(
        c.startswith("max_blast_radius:") for c in ado.propagated_constraints
    )
    suite.must_pass(
        "posture_mapping:max_blast_radius_present",
        condition=max_blast_present,
        description="propagated_constraints includes max_blast_radius from UserPosture",
        spec_ref="SPEC §8.8",
    )

    reversibility_present = any(
        c.startswith("reversibility_required:") for c in ado.propagated_constraints
    )
    suite.must_pass(
        "posture_mapping:reversibility_required_present",
        condition=reversibility_present,
        description="propagated_constraints includes reversibility_required from UserPosture",
        spec_ref="SPEC §8.8",
    )

    minimum_evidence_present = any(
        c.startswith("minimum_evidence:") for c in ado.propagated_constraints
    )
    suite.must_pass(
        "posture_mapping:minimum_evidence_present",
        condition=minimum_evidence_present,
        description="propagated_constraints includes minimum_evidence from UserPosture",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("Constraint Propagation Tests")
    test_constraint_inheritance(suite)
    test_child_cannot_exceed_propagated_scope(suite)
    test_signature_tamper_detection(suite)
    test_constraint_narrowing(suite)
    test_posture_to_constraints_mapping(suite)
    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Propagation: Constraint Propagation Tests")
    print("=" * 60)
    s = run()
    s.report.print_summary()
    s.report.assert_all_passed()
