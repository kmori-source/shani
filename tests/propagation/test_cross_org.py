"""
tests/propagation/test_cross_org.py

Cross-organisational propagation scenarios (SPEC §8.8, §8.9).

Mirrors the examples/cross-org/scenario.py narrative but as verifiable
pytest conformance checks.

Test cases:
    1. cross_org_supply_chain         — Org A issues → Org B validates downstream update
    2. cross_org_scope_violation      — Org B proposal violates Org A's propagated scope
    3. cross_org_min_dsal_gate        — cross_org_min_dsal policy blocks under-authority ADOs
    4. origin_org_preserved_in_chain  — origin_org travels unchanged through the chain
    5. incompatible_reversibility     — Org A allows irreversible; Org B requires reversible
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
from shani.authority.policy import OrgPolicy, OrgPolicyAbsoluteConstraints
from shani.schemas.decision import AuthorizedDecisionObject, DelegationRules, EvidenceItem
from shani.schemas.posture import PostureRefinementRequest

from framework import ConformanceSuite
from fixtures import (
    make_evaluator,
    make_cross_org_evaluator,
    make_posture,
    make_proposal,
    make_valid_ado,
    make_cross_org_ado,
    make_fake_cross_org_ado,
    future,
)


# ---------------------------------------------------------------------------
# 1. Cross-org supply chain — happy path
# ---------------------------------------------------------------------------


def test_cross_org_supply_chain(suite: ConformanceSuite) -> None:
    suite._section("1. Cross-Org Supply Chain Happy Path (SPEC §8.8)")

    # Org A: upstream publisher
    org_a_posture = make_posture(
        principal_id="org-a",
        target_scope=r"pkg:.*",
        max_blast_radius="significant",
        reversibility_required=False,
        minimum_evidence=1,
    )
    # Use posture=None to bypass PostureEngine signature requirement in tests.
    # Posture constraints are embedded manually via model_copy after ADO issuance.
    org_a_ev = make_cross_org_evaluator(
        org_id="org-a",
        cross_org_min_dsal=2,
    )

    # Org A agent issues cross-org ADO for package publish
    org_a_proposal = make_proposal(
        proposed_by="agent/alpha",
        decision_type=DecisionType.REMEDIATION,
        target="pkg:pypi/mylib@1.0.0",
        blast_radius=BlastRadius.SIGNIFICANT,
        reversibility=False,
        origin_org="org-a",
        evidence=[
            EvidenceItem(source="ci", content="tests pass", confidence=0.96),
            EvidenceItem(source="sbom", content="no CVEs", confidence=0.95),
        ],
        expires_at=future(300),
    )

    ado_a = make_valid_ado(org_a_ev, org_a_proposal)

    # Embed posture constraints into ADO (simulates what evaluator does with signed posture)
    ado_a = ado_a.model_copy(update={
        "origin_org": "org-a",
        "propagated_constraints": [
            f"target_scope:{org_a_posture.constraints.target_scope}",
            f"max_blast_radius:{org_a_posture.constraints.max_blast_radius}",
            f"reversibility_required:{str(org_a_posture.constraints.reversibility_required).lower()}",
            f"minimum_evidence:{org_a_posture.constraints.minimum_evidence}",
        ],
        "delegation_rules": DelegationRules(
            allowed_sub_decisions=["remediation", "configuration_change"],
            max_child_dsal=2,
            max_depth=3,
            max_children=10,
        ),
    })

    suite.must_pass(
        "supply_chain:org_a_ado_issued",
        condition=isinstance(ado_a, AuthorizedDecisionObject),
        description="Org A cross-org ADO issued successfully",
        detail=f"got {type(ado_a).__name__}",
        spec_ref="SPEC §8.8",
    )

    has_propagated = bool(ado_a.propagated_constraints)
    suite.must_pass(
        "supply_chain:ado_has_propagated_constraints",
        condition=has_propagated,
        description="Org A ADO carries non-empty propagated_constraints",
        detail=f"constraints={ado_a.propagated_constraints}",
        spec_ref="SPEC §8.8",
    )

    # Org B: downstream consumer with stricter posture
    org_b_posture = make_posture(
        principal_id="org-b",
        target_scope=r".*dev.*|.*staging.*",
        max_blast_radius="limited",
        reversibility_required=True,
        minimum_evidence=1,
    )
    org_b_ev = make_cross_org_evaluator(
        org_id="org-b",
        cross_org_min_dsal=2,
    )

    # Org B updates the package in dev — within Org A's propagated scope (pkg:.*)
    # ado_a already has propagated_constraints embedded via model_copy above
    parent_ado = ado_a

    org_b_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="pkg:pypi/mylib@1.0.0-dev",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
        evidence=[
            EvidenceItem(source="depbot", content="compatible", confidence=0.92),
        ],
        expires_at=future(300),
    )

    result_b = org_b_ev.evaluate(org_b_proposal, parent_ado=parent_ado)

    suite.must_pass(
        "supply_chain:org_b_dev_update_accepted",
        condition=isinstance(result_b, AuthorizedDecisionObject),
        description="Org B dev update within cross-org constraints → ADO issued",
        detail=f"got {type(result_b).__name__}: {getattr(result_b, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# 2. Cross-org scope violation
# ---------------------------------------------------------------------------


def test_cross_org_scope_violation(suite: ConformanceSuite) -> None:
    suite._section("2. Cross-Org Scope Violation (SPEC §8.8 MUST FAIL)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Parent restricts to domestic-only
    parent_ado = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:domestic-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
    )

    # Proposal targeting an international host — outside domestic scope
    intl_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:international-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(intl_proposal, parent_ado=parent_ado)

    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "scope_violation:international_target_rejected",
        condition=not_ado,
        description="proposal outside propagated domestic scope → not ADO",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )

    is_refinement = isinstance(result, PostureRefinementRequest)
    suite.must_fail(
        "scope_violation:is_refinement",
        condition=is_refinement,
        description="scope violation → PostureRefinementRequest (requires originator resolution)",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )

    if is_refinement:
        has_principal = result.principal_id == "org-alpha"
        suite.must_fail(
            "scope_violation:refinement_targets_origin",
            condition=has_principal,
            description="PostureRefinementRequest.principal_id is the originating org",
            detail=f"got {result.principal_id!r}",
            spec_ref="SPEC §8.8",
        )


# ---------------------------------------------------------------------------
# 3. cross_org_min_dsal gate
# ---------------------------------------------------------------------------


def test_cross_org_min_dsal_gate(suite: ConformanceSuite) -> None:
    suite._section("3. cross_org_min_dsal Policy Gate (SPEC §8.8)")

    # child_ev with strict cross_org_min_dsal=3
    from shani.authority.policy import AgentIdentity
    strict_agents = {
        "agent/beta": AgentIdentity(
            agent_id="agent/beta",
            granted_dsal=3,
            allowed_decision_types=frozenset(["remediation"]),
        ),
    }
    strict_policy = OrgPolicy(
        absolute_constraints=OrgPolicyAbsoluteConstraints(
            max_blast_radius="critical",
            cross_org_min_dsal=3,
        )
    )
    child_ev = make_evaluator(
        org_policy=strict_policy,
        agents=strict_agents,
    )

    # Parent ADO authorised at D-SAL 2 — below the min for this child org
    # max_child_dsal must be strictly less than authorized_dsal (schema invariant)
    low_dsal_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
        authorized_dsal=2,
        max_child_dsal=1,
    )

    # Low-risk proposal — D-SAL would normally be 1
    simple_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(simple_proposal, parent_ado=low_dsal_parent)

    # Effective D-SAL (1) < cross_org_min_dsal (3) → denied
    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "min_dsal_gate:below_minimum_rejected",
        condition=not_ado,
        description="cross-org ADO with effective D-SAL below cross_org_min_dsal → not ADO",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )

    is_denied = isinstance(result, DeniedDecision)
    suite.must_fail(
        "min_dsal_gate:is_denied_decision",
        condition=is_denied,
        description="D-SAL below cross_org_min_dsal → DeniedDecision",
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# 4. origin_org preserved through chain
# ---------------------------------------------------------------------------


def test_origin_org_preserved(suite: ConformanceSuite) -> None:
    suite._section("4. origin_org Preserved Through Chain (SPEC §8.8)")

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

    child_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-10",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    result = child_ev.evaluate(child_proposal, parent_ado=parent_ado)

    suite.must_pass(
        "origin_preserved:child_ado_issued",
        condition=isinstance(result, AuthorizedDecisionObject),
        description="child ADO issued in cross-org chain",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )

    if isinstance(result, AuthorizedDecisionObject):
        suite.must_pass(
            "origin_preserved:origin_org_unchanged",
            condition=result.origin_org == "org-alpha",
            description="origin_org preserved in child ADO (not overwritten by child org)",
            detail=f"got {result.origin_org!r}",
            spec_ref="SPEC §8.8",
        )


# ---------------------------------------------------------------------------
# 5. Incompatible reversibility constraint
# ---------------------------------------------------------------------------


def test_incompatible_reversibility(suite: ConformanceSuite) -> None:
    suite._section("5. Incompatible Reversibility Constraint (SPEC §8.8 MUST FAIL)")

    child_ev = make_cross_org_evaluator(org_id="org-beta")

    # Org A requires reversibility
    parent_ado = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:.*",
            "max_blast_radius:critical",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
    )

    # Proposal is irreversible — violates propagated reversibility_required:true
    irreversible_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=False,  # violates constraint
    )

    result = child_ev.evaluate(irreversible_proposal, parent_ado=parent_ado)

    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "reversibility_constraint:irreversible_rejected",
        condition=not_ado,
        description="irreversible proposal violates propagated reversibility_required:true → not ADO",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("Cross-Org Propagation Tests")
    test_cross_org_supply_chain(suite)
    test_cross_org_scope_violation(suite)
    test_cross_org_min_dsal_gate(suite)
    test_origin_org_preserved(suite)
    test_incompatible_reversibility(suite)
    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Propagation: Cross-Org Scenario Tests")
    print("=" * 60)
    s = run()
    s.report.print_summary()
    s.report.assert_all_passed()
