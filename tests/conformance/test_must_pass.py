"""
tests/conformance/test_must_pass.py

Shani Conformance: MUST PASS Tests.

Each test verifies that the implementation correctly ACCEPTS or ALLOWS
an operation that MUST succeed per the Shani specification.

Test cases:
    1. valid_posture_refinement   — AMBIGUOUS posture produces PostureRefinementRequest,
                                    not DeniedDecision; required fields present (SPEC §8.4, §8.5)
    2. proper_replay_rejection    — replay prevention works correctly end-to-end:
                                    valid ADO is accepted; replay is blocked (SPEC §5.4)
    3. dis_transition_handling    — DIS state transitions are valid; VIOLATED blocks execution;
                                    reset_to_valid() requires justification (SPEC §4.4)
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

from shani import DeniedDecision
from shani.schemas.decision import AuthorizedDecisionObject
from shani.schemas.posture import PostureOutcome, PostureRefinementRequest
from shani.schemas.state import DIS, DISStateMachine
from shani.posture.engine import PostureEngine
from shani.security.replay_store import NonceAlreadyConsumed, InMemoryNonceStore

from framework import ConformanceSuite
from fixtures import (
    make_evaluator, make_proposal, make_valid_ado, make_user_posture,
)


# ---------------------------------------------------------------------------
# 1. Valid Posture Refinement — SPEC §8.4, §8.5
# ---------------------------------------------------------------------------


def test_valid_posture_refinement(suite: ConformanceSuite) -> None:
    suite._section("1. Valid Posture Refinement (SPEC §8.4, §8.5)")

    # Build a PostureEngine that returns AMBIGUOUS by subclassing _layer1
    class AmbiguousPostureEngine(PostureEngine):
        def _layer1(self, proposal):
            return PostureOutcome.AMBIGUOUS, ["target_scope"], ["minimum_evidence"]

    posture = make_user_posture()
    engine  = AmbiguousPostureEngine(posture)
    proposal = make_proposal()
    outcome, req = engine.evaluate(proposal)

    # AMBIGUOUS must be returned (not REJECT, not PASS)
    suite.must_pass(
        "posture_refinement:outcome_is_ambiguous",
        condition=outcome == PostureOutcome.AMBIGUOUS,
        description="PostureEngine AMBIGUOUS path: outcome == AMBIGUOUS",
        detail=f"got {outcome}",
        spec_ref="SPEC §8.4",
    )

    # AMBIGUOUS must produce PostureRefinementRequest, not DeniedDecision
    is_refinement = isinstance(req, PostureRefinementRequest)
    suite.must_pass(
        "posture_refinement:result_is_refinement_request",
        condition=is_refinement,
        description="AMBIGUOUS → PostureRefinementRequest (not DeniedDecision)",
        detail=f"got {type(req).__name__}",
        spec_ref="SPEC §8.5",
    )

    if is_refinement:
        suite.must_pass(
            "posture_refinement:has_proposal_id",
            condition=bool(req.proposal_id),
            description="PostureRefinementRequest.proposal_id is non-empty",
            spec_ref="SPEC §8.5",
        )
        suite.must_pass(
            "posture_refinement:has_principal_id",
            condition=bool(req.principal_id),
            description="PostureRefinementRequest.principal_id is non-empty",
            spec_ref="SPEC §8.5",
        )
        suite.must_pass(
            "posture_refinement:has_ambiguity",
            condition=bool(req.ambiguity),
            description="PostureRefinementRequest.ambiguity explanation is present",
            spec_ref="SPEC §8.5",
        )
        suite.must_pass(
            "posture_refinement:has_matched_and_unresolved",
            condition=(
                isinstance(req.matched_constraints, list)
                and isinstance(req.unresolved, list)
            ),
            description="PostureRefinementRequest has matched_constraints and unresolved lists",
            spec_ref="SPEC §8.5",
        )

    # PostureRefinementRequest must NOT be a DeniedDecision
    from shani.core.evaluator import DeniedDecision as DD
    not_denied = not isinstance(req, DD)
    suite.must_pass(
        "posture_refinement:not_denied_decision",
        condition=not_denied,
        description="PostureRefinementRequest is a distinct type (not DeniedDecision)",
        spec_ref="SPEC §8.5",
    )

    # PostureRefinementRequest must be immutable (frozen)
    if is_refinement:
        is_immutable = False
        try:
            req.ambiguity = "tampered"  # type: ignore[misc]
        except Exception:
            is_immutable = True
        suite.must_pass(
            "posture_refinement:immutable",
            condition=is_immutable,
            description="PostureRefinementRequest is immutable (frozen dataclass/model)",
            spec_ref="SPEC §8.5",
        )

    # Valid PASS path: proposal within posture constraints must produce PASS
    broad_posture  = make_user_posture(
        target_scope="host:dev-.*",
        max_blast_radius="limited",
        reversibility_required=True,
        minimum_evidence=1,
    )
    pass_engine   = PostureEngine(broad_posture)
    valid_proposal = make_proposal(target="host:dev-42")
    pass_outcome, pass_req = pass_engine.evaluate(valid_proposal)

    suite.must_pass(
        "posture_refinement:valid_proposal_passes",
        condition=pass_outcome == PostureOutcome.PASS,
        description="valid proposal within posture constraints → PASS from PostureEngine",
        detail=f"got {pass_outcome}",
        spec_ref="SPEC §8.4",
    )

    # REJECT path: proposal outside target_scope → REJECT
    reject_proposal = make_proposal(target="host:prod-01")
    reject_outcome, reject_req = pass_engine.evaluate(reject_proposal)

    suite.must_pass(
        "posture_refinement:out_of_scope_rejected",
        condition=reject_outcome == PostureOutcome.REJECT and reject_req is None,
        description="proposal outside target_scope → REJECT (no refinement request from PostureEngine)",
        detail=f"got {reject_outcome}, req={reject_req}",
        spec_ref="SPEC §8.4",
    )


# ---------------------------------------------------------------------------
# 2. Proper Replay Rejection — SPEC §5.4
# ---------------------------------------------------------------------------


def test_proper_replay_rejection(suite: ConformanceSuite) -> None:
    suite._section("2. Proper Replay Rejection (SPEC §5.4)")

    nonce_store = InMemoryNonceStore()
    ev          = make_evaluator(nonce_store=nonce_store)
    proposal    = make_proposal()

    # Issue valid ADO — must succeed
    ado = ev.evaluate(proposal)
    suite.must_pass(
        "replay_rejection:ado_issued",
        condition=isinstance(ado, AuthorizedDecisionObject),
        description="valid proposal → ADO issued successfully",
        detail=f"got {type(ado).__name__}: {getattr(ado, 'reason', '')}",
        spec_ref="SPEC §5.4",
    )
    if not isinstance(ado, AuthorizedDecisionObject):
        return

    # verify_binding() must return True before execution
    suite.must_pass(
        "replay_rejection:verify_before_execute",
        condition=ev.verify_binding(ado, proposal),
        description="verify_binding() returns True before nonce is consumed",
        spec_ref="SPEC §5.4",
    )

    # Register execution — nonce consumed
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
        registered = True
    except Exception as exc:
        registered = False
        suite.must_pass(
            "replay_rejection:register_executed_succeeds",
            condition=False,
            description="register_executed() must succeed on first call",
            detail=str(exc),
            spec_ref="SPEC §5.4",
        )
        return

    suite.must_pass(
        "replay_rejection:register_executed_succeeds",
        condition=registered,
        description="register_executed() succeeds on first call",
        spec_ref="SPEC §5.4",
    )

    # Nonce must be recorded as consumed
    suite.must_pass(
        "replay_rejection:nonce_recorded",
        condition=nonce_store.is_consumed(ado.nonce),
        description="nonce is marked consumed in the nonce store after execution",
        spec_ref="SPEC §5.4",
    )

    # verify_binding() must return False after nonce consumed
    suite.must_pass(
        "replay_rejection:verify_after_execute_false",
        condition=not ev.verify_binding(ado, proposal),
        description="verify_binding() returns False after nonce consumed (replay detection)",
        spec_ref="SPEC §5.4",
    )

    # Replay: second register_executed must raise NonceAlreadyConsumed
    replay_correctly_blocked = False
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
    except NonceAlreadyConsumed:
        replay_correctly_blocked = True

    suite.must_pass(
        "replay_rejection:replay_raises_exception",
        condition=replay_correctly_blocked,
        description="second register_executed() raises NonceAlreadyConsumed (replay blocked)",
        spec_ref="SPEC §5.4",
    )

    # New proposal with same evaluator must still succeed (nonce store is per-ADO)
    proposal2 = make_proposal(target="host:dev-02")
    ado2 = ev.evaluate(proposal2)
    suite.must_pass(
        "replay_rejection:new_proposal_unaffected",
        condition=isinstance(ado2, AuthorizedDecisionObject),
        description="new proposal after replay is still evaluated correctly (different nonce)",
        detail=f"got {type(ado2).__name__}",
        spec_ref="SPEC §5.4",
    )


# ---------------------------------------------------------------------------
# 3. DIS Transition Handling — SPEC §4.4
# ---------------------------------------------------------------------------


def test_dis_transition_handling(suite: ConformanceSuite) -> None:
    suite._section("3. DIS Transition Handling (SPEC §4.4)")

    dis = DISStateMachine(initial=DIS.VALID)

    # Initial state is VALID
    suite.must_pass(
        "dis_transitions:initial_valid",
        condition=dis.state == DIS.VALID,
        description="DISStateMachine starts in VALID state",
        spec_ref="SPEC §4.4",
    )

    # VALID → DEGRADED is allowed
    try:
        dis.transition(DIS.DEGRADED, reason="Sensor drift detected", triggered_by="monitor")
        valid_to_degraded = dis.state == DIS.DEGRADED
    except Exception as exc:
        valid_to_degraded = False
    suite.must_pass(
        "dis_transitions:valid_to_degraded",
        condition=valid_to_degraded,
        description="DIS VALID → DEGRADED transition is allowed",
        spec_ref="SPEC §4.4",
    )

    # DEGRADED → VIOLATED is allowed
    try:
        dis.transition(DIS.VIOLATED, reason="Integrity breach confirmed", triggered_by="audit")
        degraded_to_violated = dis.state == DIS.VIOLATED
    except Exception as exc:
        degraded_to_violated = False
    suite.must_pass(
        "dis_transitions:degraded_to_violated",
        condition=degraded_to_violated,
        description="DIS DEGRADED → VIOLATED transition is allowed",
        spec_ref="SPEC §4.4",
    )

    # VIOLATED state blocks execution
    ev_violated = make_evaluator(dis_machine=dis)
    proposal = make_proposal()
    result = ev_violated.evaluate(proposal)
    suite.must_pass(
        "dis_transitions:violated_blocks_execution",
        condition=isinstance(result, DeniedDecision),
        description="DIS VIOLATED state → evaluate() returns DeniedDecision",
        detail=f"got {type(result).__name__}: {getattr(result, 'reason', '')}",
        spec_ref="SPEC §4.4",
    )

    # VIOLATED → VALID via transition() must be blocked
    transition_blocked = False
    try:
        dis.transition(DIS.VALID, reason="Attempt to bypass")
    except ValueError:
        transition_blocked = True
    suite.must_pass(
        "dis_transitions:violated_to_valid_via_transition_blocked",
        condition=transition_blocked,
        description="DIS VIOLATED → VALID via transition() raises ValueError (must use reset_to_valid)",
        spec_ref="SPEC §4.4",
    )

    # reset_to_valid() without justification must fail
    empty_justification_blocked = False
    try:
        dis.reset_to_valid(justification="", authorized_by="admin")
    except ValueError:
        empty_justification_blocked = True
    suite.must_pass(
        "dis_transitions:reset_requires_justification",
        condition=empty_justification_blocked,
        description="reset_to_valid() with empty justification raises ValueError",
        spec_ref="SPEC §4.4",
    )

    # reset_to_valid() without authority must fail
    empty_authority_blocked = False
    try:
        dis.reset_to_valid(justification="Incident resolved", authorized_by="")
    except ValueError:
        empty_authority_blocked = True
    suite.must_pass(
        "dis_transitions:reset_requires_authority",
        condition=empty_authority_blocked,
        description="reset_to_valid() with empty authorized_by raises ValueError",
        spec_ref="SPEC §4.4",
    )

    # Proper reset: reset_to_valid() with valid args succeeds
    try:
        dis.reset_to_valid(
            justification="Incident fully resolved and root cause addressed.",
            authorized_by="ciso@example.com",
        )
        reset_ok = dis.state == DIS.VALID
    except Exception as exc:
        reset_ok = False
    suite.must_pass(
        "dis_transitions:proper_reset_succeeds",
        condition=reset_ok,
        description="reset_to_valid() with valid justification and authority succeeds → DIS.VALID",
        spec_ref="SPEC §4.4",
    )

    # After reset, evaluate() should accept valid proposals again
    ev_reset = make_evaluator(dis_machine=dis)
    result_after = ev_reset.evaluate(make_proposal())
    suite.must_pass(
        "dis_transitions:execution_allowed_after_reset",
        condition=isinstance(result_after, AuthorizedDecisionObject),
        description="after DIS reset to VALID, evaluate() accepts valid proposals again",
        detail=f"got {type(result_after).__name__}: {getattr(result_after, 'reason', '')}",
        spec_ref="SPEC §4.4",
    )

    # Transition history must be recorded
    history_recorded = len(dis.history) >= 3  # DEGRADED + VIOLATED + RESET
    suite.must_pass(
        "dis_transitions:history_recorded",
        condition=history_recorded,
        description=f"DIS transition history records all transitions ({len(dis.history)} entries)",
        spec_ref="SPEC §4.4",
    )

    # VALID → VIOLATED shortcut transition (skip DEGRADED)
    dis2 = DISStateMachine(initial=DIS.VALID)
    try:
        dis2.transition(DIS.VIOLATED, reason="Emergency kill")
        valid_to_violated = dis2.state == DIS.VIOLATED
    except Exception:
        valid_to_violated = False
    suite.must_pass(
        "dis_transitions:valid_to_violated_direct",
        condition=valid_to_violated,
        description="DIS VALID → VIOLATED direct transition is allowed",
        spec_ref="SPEC §4.4",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("MUST PASS Conformance Tests")

    test_valid_posture_refinement(suite)
    test_proper_replay_rejection(suite)
    test_dis_transition_handling(suite)

    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Shani MUST PASS Conformance Tests")
    print("=" * 60)

    suite = run()
    suite.report.print_summary()
    suite.report.assert_all_passed()
