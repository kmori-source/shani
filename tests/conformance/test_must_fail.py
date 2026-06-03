"""
tests/conformance/test_must_fail.py

Shani Conformance: MUST FAIL Tests.

Each test verifies that the implementation correctly REJECTS or DENIES
an operation that MUST NOT succeed per the Shani specification.

Test cases:
    1. expired_ado          — verify_binding() returns False for expired ADO (SPEC §5.3)
    2. reused_ado_nonce     — replay via nonce reuse is blocked (SPEC §5.4)
    3. missing_propagated_constraints — cross-org ADO without propagated_constraints
                              is treated as AMBIGUOUS (SPEC §8.8, §8.9)
    4. invalid_signature    — tampered signature field → verify_binding() False (SPEC §4.5)
    5. dsal_escalation      — child ADO cannot escalate beyond parent's max_child_dsal (SPEC §6.2)
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, _HERE)

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
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

from shani import DeniedDecision, BlastRadius, DecisionType
from shani.schemas.decision import AuthorizedDecisionObject, DelegationRules
from shani.schemas.posture import PostureRefinementRequest
from shani.security.replay_store import NonceAlreadyConsumed

from framework import ConformanceSuite
from fixtures import (
    make_evaluator, make_proposal, make_valid_ado,
    make_expired_ado, make_cross_org_ado,
    future, past,
)


# ---------------------------------------------------------------------------
# 1. Expired ADO — SPEC §5.3
# ---------------------------------------------------------------------------


def test_expired_ado(suite: ConformanceSuite) -> None:
    suite._section("1. Expired ADO (SPEC §5.3)")

    ev = make_evaluator()
    expired_ado = make_expired_ado(ev)
    proposal    = make_proposal()

    # is_expired() must be True
    suite.must_fail(
        "expired_ado:is_expired",
        condition=expired_ado.is_expired(),
        description="expired ADO: is_expired() returns True",
        spec_ref="SPEC §5.3",
    )

    # verify_binding() must return False for expired ADO
    result = ev.verify_binding(expired_ado, proposal)
    suite.must_fail(
        "expired_ado:verify_binding",
        condition=not result,
        description="expired ADO: verify_binding() returns False",
        detail=f"verify_binding returned {result}",
        spec_ref="SPEC §5.3",
    )

    # evaluate() must NOT return an ADO when presented with an expired-flag check
    # (DIS gate or direct expiry check must catch it).
    # We test the time_remaining_seconds() accessor.
    suite.must_fail(
        "expired_ado:time_remaining",
        condition=expired_ado.time_remaining_seconds() == 0.0,
        description="expired ADO: time_remaining_seconds() == 0.0",
        spec_ref="SPEC §5.3",
    )


# ---------------------------------------------------------------------------
# 2. Reused ADO Nonce — SPEC §5.4
# ---------------------------------------------------------------------------


def test_reused_ado_nonce(suite: ConformanceSuite) -> None:
    suite._section("2. Reused ADO Nonce (SPEC §5.4)")

    ev      = make_evaluator()
    proposal = make_proposal()
    ado     = make_valid_ado(ev, proposal)

    # First registration must succeed
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
        first_ok = True
    except Exception as exc:
        first_ok = False
        suite.must_pass(
            "reused_nonce:first_registration",
            condition=False,
            description="first register_executed() must succeed",
            detail=str(exc),
            spec_ref="SPEC §5.4",
        )
        return

    suite.must_pass(
        "reused_nonce:first_registration",
        condition=first_ok,
        description="first register_executed() succeeds",
        spec_ref="SPEC §5.4",
    )

    # Second registration with the same ADO must raise NonceAlreadyConsumed
    replay_blocked = False
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
    except NonceAlreadyConsumed:
        replay_blocked = True
    except Exception:
        replay_blocked = False

    suite.must_fail(
        "reused_nonce:second_registration_blocked",
        condition=replay_blocked,
        description="replay: register_executed() raises NonceAlreadyConsumed on second call",
        spec_ref="SPEC §5.4",
    )

    # verify_binding() must return False after nonce consumed
    binding_invalid = not ev.verify_binding(ado, proposal)
    suite.must_fail(
        "reused_nonce:verify_binding_post_consume",
        condition=binding_invalid,
        description="replay: verify_binding() returns False after nonce is consumed",
        spec_ref="SPEC §5.4",
    )

    # Nonce store must report nonce as consumed
    nonce_consumed = ev._nonce_store.is_consumed(ado.nonce)
    suite.must_fail(
        "reused_nonce:nonce_store_reports_consumed",
        condition=nonce_consumed,
        description="replay: nonce store records nonce as consumed",
        spec_ref="SPEC §5.4",
    )

    # register_executed(str) legacy path must be disallowed (SPEC §5.4)
    str_path_blocked = False
    try:
        ev.register_executed(ado.decision_id, agent_id="agent/conformance")
    except TypeError:
        str_path_blocked = True
    suite.must_fail(
        "reused_nonce:string_path_disallowed",
        condition=str_path_blocked,
        description="register_executed(str) raises TypeError — legacy path removed per SPEC §5.4",
        spec_ref="SPEC §5.4",
    )


# ---------------------------------------------------------------------------
# 3. Missing propagated_constraints on cross-org ADO — SPEC §8.8, §8.9
# ---------------------------------------------------------------------------


def test_missing_propagated_constraints(suite: ConformanceSuite) -> None:
    suite._section("3. Missing propagated_constraints (SPEC §8.8, §8.9)")

    from shani.authority.policy import OrgPolicy, OrgPolicyAbsoluteConstraints
    from shani.schemas.decision import DecisionType

    # Build a parent ADO that is cross-org but has NO propagated_constraints.
    # An evaluator that processes a child proposal under this parent MUST return
    # PostureRefinementRequest (AMBIGUOUS), not DeniedDecision or ADO.

    org_policy = OrgPolicy(
        absolute_constraints=OrgPolicyAbsoluteConstraints(
            max_blast_radius="critical",
            cross_org_min_dsal=2,
        )
    )
    parent_ev = make_evaluator(org_policy=org_policy)
    child_ev  = make_evaluator(org_policy=org_policy)

    # Issue parent ADO (no cross-org constraint propagation)
    # Use REMEDIATION (base D-SAL 1) — agent/conformance has granted_dsal=3,
    # which is insufficient for POLICY_UPDATE (base D-SAL 4).
    parent_proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
    )
    parent_ado = make_valid_ado(parent_ev, parent_proposal)

    # Manually add origin_org but leave propagated_constraints empty
    cross_org_parent = parent_ado.model_copy(update={
        "origin_org": "org-alpha",
        "propagated_constraints": [],
    })

    # Child proposal submitted to child evaluator under this cross-org parent
    child_proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
    )
    result = child_ev.evaluate(child_proposal, parent_ado=cross_org_parent)

    is_refinement = isinstance(result, PostureRefinementRequest)
    suite.must_fail(
        "missing_propagated_constraints:result_is_refinement",
        condition=is_refinement,
        description=(
            "cross-org ADO without propagated_constraints → PostureRefinementRequest (AMBIGUOUS)"
        ),
        detail=f"got {type(result).__name__}",
        spec_ref="SPEC §8.8, §8.9",
    )

    if is_refinement:
        has_ambiguity = bool(result.ambiguity)
        suite.must_fail(
            "missing_propagated_constraints:refinement_has_ambiguity",
            condition=has_ambiguity,
            description="PostureRefinementRequest carries ambiguity explanation",
            spec_ref="SPEC §8.9",
        )
        references_propagated = "propagated_constraints" in result.unresolved
        suite.must_fail(
            "missing_propagated_constraints:unresolved_lists_field",
            condition=references_propagated,
            description="PostureRefinementRequest.unresolved includes 'propagated_constraints'",
            spec_ref="SPEC §8.9",
        )

    # Direct structural check: cross-org ADO with empty constraints is detectable
    is_detectable = (
        cross_org_parent.origin_org is not None
        and len(cross_org_parent.propagated_constraints) == 0
    )
    suite.must_fail(
        "missing_propagated_constraints:detectable_from_ado",
        condition=is_detectable,
        description="cross-org ADO: origin_org set + empty propagated_constraints is detectable",
        spec_ref="SPEC §8.8",
    )


# ---------------------------------------------------------------------------
# 4. Invalid Signature — SPEC §4.5
# ---------------------------------------------------------------------------


def test_invalid_signature(suite: ConformanceSuite) -> None:
    suite._section("4. Invalid Signature (SPEC §4.5)")

    ev       = make_evaluator()
    proposal = make_proposal()
    ado      = make_valid_ado(ev, proposal)

    # Baseline: valid ADO passes
    baseline_ok = ev.verify_binding(ado, proposal)
    suite.must_pass(
        "invalid_signature:baseline_valid",
        condition=baseline_ok,
        description="baseline: valid ADO passes verify_binding()",
        spec_ref="SPEC §4.5",
    )

    # Tampered signature field
    tampered_sig = ado.model_copy(update={"signature": "deadbeef" * 16})
    suite.must_fail(
        "invalid_signature:tampered_sig",
        condition=not ev.verify_binding(tampered_sig, proposal),
        description="tampered signature → verify_binding() returns False",
        spec_ref="SPEC §4.5",
    )

    # Tampered authority field (signature covers authority)
    tampered_authority = ado.model_copy(update={"authority": "ATTACKER-LEVEL"})
    suite.must_fail(
        "invalid_signature:tampered_authority",
        condition=not ev.verify_binding(tampered_authority, proposal),
        description="tampered authority field → verify_binding() returns False (signature mismatch)",
        spec_ref="SPEC §4.5",
    )

    # Tampered authorized_dsal (D-SAL escalation via field mutation)
    if ado.authorized_dsal < 4:
        tampered_dsal = ado.model_copy(update={"authorized_dsal": 4})
        suite.must_fail(
            "invalid_signature:tampered_dsal",
            condition=not ev.verify_binding(tampered_dsal, proposal),
            description="tampered authorized_dsal → verify_binding() returns False (escalation blocked)",
            spec_ref="SPEC §4.5",
        )

    # Wrong proposal hash (fake ADO targeting different proposal)
    tampered_hash = ado.model_copy(update={"proposal_hash": "0" * 64})
    suite.must_fail(
        "invalid_signature:wrong_proposal_hash",
        condition=not ev.verify_binding(tampered_hash, proposal),
        description="mismatched proposal_hash → verify_binding() returns False",
        spec_ref="SPEC §4.5",
    )

    # Proposal mismatch check (proposal.canonical_hash() != ado.proposal_hash)
    different_proposal = make_proposal(target="host:prod-99")
    suite.must_fail(
        "invalid_signature:proposal_mismatch",
        condition=not ev.verify_binding(ado, different_proposal),
        description="proposal canonical_hash mismatch → verify_binding() returns False",
        spec_ref="SPEC §4.5",
    )


# ---------------------------------------------------------------------------
# 5. D-SAL Escalation in Delegation — SPEC §6.2
# ---------------------------------------------------------------------------


def test_dsal_escalation(suite: ConformanceSuite) -> None:
    suite._section("5. D-SAL Escalation in Delegation (SPEC §6.2)")

    from shani.schemas.decision import DecisionType

    ev = make_evaluator(max_dsal=3)

    # Issue parent ADO with delegation enabled, max_child_dsal=1
    # blast_radius=CRITICAL raises risk score → effective D-SAL 2 (SUPERVISED),
    # which is required for delegation (DSAL.allows_delegation requires >= SUPERVISED).
    parent_proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        delegation=True,
        blast_radius=BlastRadius.CRITICAL,
    )
    parent_ado = make_valid_ado(ev, parent_proposal)

    # Manually construct a parent ADO with strict delegation limits
    low_rules = DelegationRules(
        allowed_sub_decisions=["remediation"],
        max_child_dsal=1,
        max_depth=1,
        max_children=3,
    )
    restricted_parent = parent_ado.model_copy(update={"delegation_rules": low_rules})

    # Child proposal that would require effective D-SAL > max_child_dsal=1
    # We use POLICY_UPDATE (base D-SAL 3) to force escalation above the limit
    child_proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        blast_radius=BlastRadius.CRITICAL,  # +2 modifier → D-SAL ≥ 3
        reversibility=False,  # +1 modifier
    )
    result = ev.evaluate(child_proposal, parent_ado=restricted_parent)

    is_denied = isinstance(result, DeniedDecision)
    suite.must_fail(
        "dsal_escalation:child_exceeds_max_child_dsal",
        condition=is_denied,
        description="child proposal with effective D-SAL > parent max_child_dsal → DeniedDecision",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )

    # DelegationRules schema invariant: max_child_dsal must be < authorized_dsal
    from shani.schemas.decision import ExecContext, IntentBinding
    from datetime import datetime, timezone, timedelta
    import uuid
    escalation_blocked = False
    try:
        AuthorizedDecisionObject(
            decision_id=str(uuid.uuid4()),
            proposal_hash="a" * 64,
            signature="b" * 88,
            authority="test",
            authorized_dsal=2,
            delegation_rules=DelegationRules(
                allowed_sub_decisions=["remediation"],
                max_child_dsal=2,   # equal to authorized_dsal — MUST be rejected
                max_depth=1,
                max_children=1,
            ),
            nonce="c" * 64,
            issued_at=datetime.now(tz=timezone.utc),
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
            exec_context=ExecContext(
                decision_type=DecisionType.REMEDIATION,
                intent_binding=IntentBinding(
                    intent="test",
                    target="host:dev-01",
                    scope_summary="test",
                    expected_effect="test",
                    reversibility=True,
                ),
            ),
        )
    except (ValueError, Exception):
        escalation_blocked = True

    suite.must_fail(
        "dsal_escalation:schema_invariant_max_child_dsal",
        condition=escalation_blocked,
        description=(
            "ADO schema: max_child_dsal == authorized_dsal raises ValueError "
            "(delegation cannot escalate privileges)"
        ),
        spec_ref="SPEC §6.2",
    )

    # Fan-out attack: child count exceeding max_children must be blocked
    fan_out_rules = DelegationRules(
        allowed_sub_decisions=["remediation"],
        max_child_dsal=1,
        max_depth=2,
        max_children=1,  # only 1 child allowed
    )
    fanout_parent = parent_ado.model_copy(update={"delegation_rules": fan_out_rules})

    child1 = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-02",
    )
    child2 = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-03",
    )

    # First child should succeed (max_children=1 not yet reached)
    r1 = ev.evaluate(child1, parent_ado=fanout_parent)
    first_child_ok = isinstance(r1, AuthorizedDecisionObject)
    suite.must_pass(
        "dsal_escalation:fanout_first_child_allowed",
        condition=first_child_ok,
        description="fan-out: first child (within max_children=1) is allowed",
        detail=f"got {type(r1).__name__}: {getattr(r1, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )

    # Second child exceeds max_children — must be blocked
    r2 = ev.evaluate(child2, parent_ado=fanout_parent)
    fanout_blocked = isinstance(r2, DeniedDecision)
    suite.must_fail(
        "dsal_escalation:fanout_second_child_blocked",
        condition=fanout_blocked,
        description="fan-out: second child exceeds max_children=1 → DeniedDecision",
        detail=f"got {type(r2).__name__}: {getattr(r2, 'reason', '')}",
        spec_ref="SPEC §6.2",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("MUST FAIL Conformance Tests")

    test_expired_ado(suite)
    test_reused_ado_nonce(suite)
    test_missing_propagated_constraints(suite)
    test_invalid_signature(suite)
    test_dsal_escalation(suite)

    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Shani MUST FAIL Conformance Tests")
    print("=" * 60)

    suite = run()
    suite.report.print_summary()
    suite.report.assert_all_passed()
