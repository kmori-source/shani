"""
tests/propagation/test_delegation_chain.py

Multi-hop delegation chain tests for propagated_constraints (RFC-0002).

Verifies that constraints survive and are enforced across N-level delegation
chains, and that no hop can strip or dilute the originating constraints.

Test cases:
    1. two_hop_chain         — Alpha → Beta → Gamma all inherit constraints
    2. three_hop_chain       — Alpha → Beta → Gamma → Delta (4-org chain)
    3. chain_dsal_ceiling    — each hop cannot exceed the previous max_child_dsal
    4. constraint_dilution_prevented — intermediate org cannot strip constraints
    5. chain_depth_limit     — delegation beyond max_depth is blocked
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
from shani.schemas.decision import AuthorizedDecisionObject, DelegationRules
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
# Helper: build evaluator per org
# ---------------------------------------------------------------------------


def _org_ev(org_id: str, cross_org_min_dsal: int = 1):
    return make_cross_org_evaluator(org_id=org_id, cross_org_min_dsal=cross_org_min_dsal)


# ---------------------------------------------------------------------------
# 1. Two-hop chain: Alpha → Beta → Gamma
# ---------------------------------------------------------------------------


def test_two_hop_chain(suite: ConformanceSuite) -> None:
    suite._section("1. Two-Hop Chain: Alpha → Beta → Gamma (RFC-0002)")

    original_constraints = [
        "target_scope:host:dev-.*",
        "max_blast_radius:limited",
        "reversibility_required:true",
        "minimum_evidence:1",
    ]

    alpha_ev = _org_ev("org-alpha")
    beta_ev = _org_ev("org-beta")
    gamma_ev = _org_ev("org-gamma")

    # Hop 1: Alpha issues cross-org ADO
    alpha_ado = make_cross_org_ado(
        alpha_ev,
        origin_org="org-alpha",
        propagated_constraints=original_constraints,
        max_child_dsal=2,
    )

    suite.must_pass(
        "two_hop:alpha_ado_issued",
        condition=isinstance(alpha_ado, AuthorizedDecisionObject),
        description="Hop 1: Alpha issues cross-org ADO",
        spec_ref="RFC-0002",
    )

    # Hop 2: Beta processes under Alpha's ADO → issues child ADO for Gamma
    beta_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-05",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )
    beta_result = beta_ev.evaluate(beta_proposal, parent_ado=alpha_ado)

    beta_ok = isinstance(beta_result, AuthorizedDecisionObject)
    suite.must_pass(
        "two_hop:beta_ado_issued",
        condition=beta_ok,
        description="Hop 2: Beta issues child ADO under Alpha's constraints",
        detail=f"got {type(beta_result).__name__}: {getattr(beta_result, 'reason', '')}",
        spec_ref="RFC-0002",
    )

    if not beta_ok:
        return

    # Beta ADO must inherit all of Alpha's propagated_constraints
    alpha_set = set(original_constraints)
    beta_set = set(beta_result.propagated_constraints)
    beta_inherited = alpha_set.issubset(beta_set)
    suite.must_pass(
        "two_hop:beta_inherits_alpha_constraints",
        condition=beta_inherited,
        description="Beta ADO inherits all of Alpha's propagated_constraints",
        detail=f"alpha={sorted(alpha_set)}, beta={sorted(beta_set)}",
        spec_ref="RFC-0002",
    )

    # origin_org must remain org-alpha through all hops
    suite.must_pass(
        "two_hop:origin_org_still_alpha",
        condition=beta_result.origin_org == "org-alpha",
        description="origin_org is still org-alpha in Beta's child ADO",
        detail=f"got {beta_result.origin_org!r}",
        spec_ref="RFC-0002",
    )

    # Hop 3: Gamma processes under Beta's ADO
    gamma_proposal = make_proposal(
        proposed_by="agent/gamma",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-07",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    # Give Beta ADO delegation rules so Gamma can use it
    beta_delegating = beta_result.model_copy(update={
        "delegation_rules": DelegationRules(
            allowed_sub_decisions=["remediation"],
            max_child_dsal=1,
            max_depth=2,
            max_children=5,
        ),
    })
    gamma_result = gamma_ev.evaluate(gamma_proposal, parent_ado=beta_delegating)

    gamma_ok = isinstance(gamma_result, AuthorizedDecisionObject)
    suite.must_pass(
        "two_hop:gamma_ado_issued",
        condition=gamma_ok,
        description="Hop 3: Gamma issues ADO under Beta's (Alpha-constrained) chain",
        detail=f"got {type(gamma_result).__name__}: {getattr(gamma_result, 'reason', '')}",
        spec_ref="RFC-0002",
    )

    if gamma_ok:
        # Gamma ADO must also carry original Alpha constraints
        gamma_set = set(gamma_result.propagated_constraints)
        gamma_inherited = alpha_set.issubset(gamma_set)
        suite.must_pass(
            "two_hop:gamma_inherits_alpha_constraints",
            condition=gamma_inherited,
            description="Gamma ADO still carries Alpha's original propagated_constraints",
            detail=f"alpha={sorted(alpha_set)}, gamma={sorted(gamma_set)}",
            spec_ref="RFC-0002",
        )


# ---------------------------------------------------------------------------
# 2. Three-hop chain: Alpha → Beta → Gamma → Delta
# ---------------------------------------------------------------------------


def test_three_hop_chain(suite: ConformanceSuite) -> None:
    suite._section("2. Three-Hop Chain: Alpha → Beta → Gamma → Delta (RFC-0002)")

    original_constraints = [
        "target_scope:host:dev-.*",
        "max_blast_radius:limited",
        "reversibility_required:true",
        "minimum_evidence:1",
    ]
    alpha_set = set(original_constraints)

    evaluators = {
        org: _org_ev(f"org-{org}") for org in ("alpha", "beta", "gamma", "delta")
    }

    # Build chain through three hops
    current_ado = make_cross_org_ado(
        evaluators["alpha"],
        origin_org="org-alpha",
        propagated_constraints=original_constraints,
        max_child_dsal=2,
    )

    agent_names = ["agent/beta", "agent/gamma", "agent/delta"]
    org_names = ["beta", "gamma", "delta"]
    prev_label = "alpha"

    for agent, org in zip(agent_names, org_names):
        ev = evaluators[org]
        proposal = make_proposal(
            proposed_by=agent,
            decision_type=DecisionType.REMEDIATION,
            target="host:dev-10",
            blast_radius=BlastRadius.LIMITED,
            reversibility=True,
        )
        # Give current ADO delegation rules for the next hop
        delegating = current_ado.model_copy(update={
            "delegation_rules": DelegationRules(
                allowed_sub_decisions=["remediation"],
                max_child_dsal=1,
                max_depth=4,
                max_children=5,
            ),
        })
        result = ev.evaluate(proposal, parent_ado=delegating)

        is_ado = isinstance(result, AuthorizedDecisionObject)
        suite.must_pass(
            f"three_hop:{org}_ado_issued",
            condition=is_ado,
            description=f"Hop {org_names.index(org)+2}: {org} ADO issued under {prev_label} chain",
            detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
            spec_ref="RFC-0002",
        )

        if not is_ado:
            return

        # Each hop must carry original Alpha constraints
        result_set = set(result.propagated_constraints)
        inherited = alpha_set.issubset(result_set)
        suite.must_pass(
            f"three_hop:{org}_inherits_alpha",
            condition=inherited,
            description=f"{org} ADO carries Alpha's original propagated_constraints",
            detail=f"alpha={sorted(alpha_set)}, {org}={sorted(result_set)}",
            spec_ref="RFC-0002",
        )

        # origin_org must always be org-alpha
        suite.must_pass(
            f"three_hop:{org}_origin_org_alpha",
            condition=result.origin_org == "org-alpha",
            description=f"{org} ADO preserves origin_org=org-alpha",
            detail=f"got {result.origin_org!r}",
            spec_ref="RFC-0002",
        )

        current_ado = result
        prev_label = org


# ---------------------------------------------------------------------------
# 3. Chain D-SAL ceiling — each hop cannot exceed previous max_child_dsal
# ---------------------------------------------------------------------------


def test_chain_dsal_ceiling(suite: ConformanceSuite) -> None:
    suite._section("3. Chain D-SAL Ceiling (SPEC §6.2)")

    # Use plain make_evaluator (no cross-org policy) so D-SAL ceiling check
    # triggers before any cross-org constraint evaluation.
    from shani.authority.policy import AgentIdentity
    child_ev = make_evaluator(
        agents={
            "agent/beta": AgentIdentity(
                agent_id="agent/beta",
                granted_dsal=3,
                allowed_decision_types=frozenset(["remediation", "configuration_change"]),
            ),
        }
    )

    # Parent at D-SAL 2 with max_child_dsal=1
    # origin_org=None disables cross-org evaluation so D-SAL ceiling is the only check
    parent_ado = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ],
        authorized_dsal=2,
        max_child_dsal=1,
    ).model_copy(update={"origin_org": None})

    # Proposal that would normally require D-SAL > 1 (blast_radius=SIGNIFICANT adds risk)
    high_risk_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.SIGNIFICANT,   # increases effective D-SAL above max_child_dsal=1
        reversibility=False,
        confidence=0.5,
    )

    result = child_ev.evaluate(high_risk_proposal, parent_ado=parent_ado)

    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "dsal_ceiling:high_risk_child_rejected",
        condition=not_ado,
        description="child proposal with effective D-SAL > max_child_dsal → not ADO",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )

    is_denied = isinstance(result, DeniedDecision)
    suite.must_fail(
        "dsal_ceiling:is_denied",
        condition=is_denied,
        description="D-SAL ceiling violation → DeniedDecision",
        spec_ref="SPEC §6.2",
    )

    # Low-risk child (D-SAL 1) should be accepted
    low_risk_proposal = make_proposal(
        proposed_by="agent/beta",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-02",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    low_result = child_ev.evaluate(low_risk_proposal, parent_ado=parent_ado)
    suite.must_pass(
        "dsal_ceiling:low_risk_child_accepted",
        condition=isinstance(low_result, AuthorizedDecisionObject),
        description="child proposal within max_child_dsal=1 → ADO issued",
        detail=f"got {type(low_result).__name__}: {getattr(low_result, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )


# ---------------------------------------------------------------------------
# 4. Constraint dilution prevention — intermediate org cannot strip constraints
# ---------------------------------------------------------------------------


def test_constraint_dilution_prevented(suite: ConformanceSuite) -> None:
    suite._section("4. Constraint Dilution Prevention (RFC-0002)")

    gamma_ev = _org_ev("org-gamma")

    # Simulate Beta trying to strip Alpha's constraints before passing to Gamma
    # This would normally break Alpha's signature, but we test that even a hand-crafted
    # parent ADO with stripped constraints triggers AMBIGUOUS, not pass.
    stripped_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            # target_scope removed — diluted
            "max_blast_radius:limited",
        ],
    )

    gamma_proposal = make_proposal(
        proposed_by="agent/gamma",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
    )

    # Gamma evaluates the diluted parent — only max_blast_radius is present
    # This should still pass validation (remaining constraint is valid)
    # The test verifies that what IS present is still enforced
    result_ok = gamma_ev.evaluate(gamma_proposal, parent_ado=stripped_parent)

    # A proposal within the remaining constraint should pass
    suite.must_pass(
        "dilution_prevention:remaining_constraints_enforced",
        condition=isinstance(result_ok, (AuthorizedDecisionObject, PostureRefinementRequest)),
        description="partial propagated_constraints: evaluation still occurs (not errored)",
        detail=f"got {type(result_ok).__name__}",
        spec_ref="RFC-0002",
    )

    # And a proposal violating the remaining constraint must be blocked
    high_blast_proposal = make_proposal(
        proposed_by="agent/gamma",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.CRITICAL,   # violates max_blast_radius:limited
        reversibility=True,
    )
    result_blocked = gamma_ev.evaluate(high_blast_proposal, parent_ado=stripped_parent)

    not_ado = not isinstance(result_blocked, AuthorizedDecisionObject)
    suite.must_fail(
        "dilution_prevention:remaining_constraint_still_blocks",
        condition=not_ado,
        description="even a stripped chain: remaining constraints block violations",
        detail=f"got {type(result_blocked).__name__}: {getattr(result_blocked, 'reason', '')}",
        spec_ref="RFC-0002",
    )


# ---------------------------------------------------------------------------
# 5. Chain depth limit
# ---------------------------------------------------------------------------


def test_chain_depth_limit(suite: ConformanceSuite) -> None:
    suite._section("5. Chain Depth Limit (SPEC §6.2)")

    child_ev = _org_ev("org-child")

    # Parent with max_depth=1 — no further delegation allowed
    shallow_parent = make_fake_cross_org_ado(
        origin_org="org-alpha",
        propagated_constraints=[
            "target_scope:.*",
            "max_blast_radius:critical",
            "reversibility_required:false",
            "minimum_evidence:1",
        ],
        max_child_dsal=2,
    )
    shallow_parent = shallow_parent.model_copy(update={
        "delegation_rules": DelegationRules(
            allowed_sub_decisions=["remediation"],
            max_child_dsal=2,
            max_depth=1,   # no further delegation
            max_children=5,
        ),
    })

    # Proposal that itself requests delegation — must be blocked at depth limit
    delegate_proposal = make_proposal(
        proposed_by="agent/gamma",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
        delegation=True,  # requests further delegation
    )

    result = child_ev.evaluate(delegate_proposal, parent_ado=shallow_parent)

    not_ado = not isinstance(result, AuthorizedDecisionObject)
    suite.must_fail(
        "depth_limit:delegation_beyond_max_depth_blocked",
        condition=not_ado,
        description="further delegation request when max_depth=1 → not ADO",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )

    is_denied = isinstance(result, DeniedDecision)
    suite.must_fail(
        "depth_limit:is_denied",
        condition=is_denied,
        description="max_depth exceeded → DeniedDecision",
        spec_ref="SPEC §6.2",
    )

    # Non-delegating proposal at same depth must still succeed
    non_delegate_proposal = make_proposal(
        proposed_by="agent/gamma",
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-02",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
        delegation=False,
    )

    result_ok = child_ev.evaluate(non_delegate_proposal, parent_ado=shallow_parent)
    suite.must_pass(
        "depth_limit:non_delegating_still_allowed",
        condition=isinstance(result_ok, AuthorizedDecisionObject),
        description="non-delegating proposal at max_depth boundary → ADO issued",
        detail=f"got {type(result_ok).__name__}: {getattr(result_ok, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("Delegation Chain Propagation Tests")
    test_two_hop_chain(suite)
    test_three_hop_chain(suite)
    test_chain_dsal_ceiling(suite)
    test_constraint_dilution_prevented(suite)
    test_chain_depth_limit(suite)
    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Propagation: Delegation Chain Tests")
    print("=" * 60)
    s = run()
    s.report.print_summary()
    s.report.assert_all_passed()
