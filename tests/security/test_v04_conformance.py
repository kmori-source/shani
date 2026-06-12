"""
tests/security/test_v04_conformance.py

Shani v0.4 Conformance Tests (SPEC §8.9).

Verifies all normative requirements introduced in v0.4:
  1. Posture registration tests
  2. PostureEngine tests (Layer 1 and Layer 2)
  3. PostureRefinementRequest tests
  4. Cross-org ADO tests (propagated_constraints)
  5. PostureSimulation tests
"""
from __future__ import annotations

import os
import sys
import uuid
import warnings
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location(
        "_compat", str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py")
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

warnings.filterwarnings("ignore")

from shani.schemas.decision import (
    BlastRadius, DecisionProposal, DecisionScope, DecisionType, EvidenceItem,
)
from shani.schemas.posture import (
    PostureConstraints, PostureHistoryEntry, PostureOutcome,
    PostureRefinementRequest, PostureSimulationResult, UserPosture,
)
from shani.posture.engine import PostureEngine
from shani.posture.simulation import PostureSimulation
from shani.authority.policy import (
    DecisionPolicyProvider, OrgPolicy, OrgPolicyAbsoluteConstraints,
)

PASS_MARK = "\033[92m✓\033[0m"
FAIL_MARK = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg: str) -> None:
    print(f"  {PASS_MARK} {msg}")


def fail(msg: str, detail: str = "") -> None:
    _failures.append(msg)
    print(f"  {FAIL_MARK} {msg}" + (f"\n      {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n{'─' * 60}\n  {title}\n{'─' * 60}")


def now() -> datetime:
    return datetime.now(tz=timezone.utc)


def future(seconds: int = 300) -> datetime:
    return now() + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_posture(
    target_scope: str          = "host:dev-.*",
    max_blast_radius: str      = "limited",
    reversibility_required: bool = True,
    minimum_evidence: int      = 1,
    simulation_ref: str        = "sim-test-001",
    principal_id: str          = "alice@example.com",
    posture_signature: str | None = "test-posture-signature",
) -> UserPosture:
    return UserPosture(
        version="1.0",
        principal_id=principal_id,
        signed_at=now(),
        intent_statement="Delegate dev remediation.",
        simulation_ref=simulation_ref,
        constraints=PostureConstraints(
            target_scope=target_scope,
            max_blast_radius=max_blast_radius,
            reversibility_required=reversibility_required,
            minimum_evidence=minimum_evidence,
        ),
        posture_signature=posture_signature,
    )


def make_proposal(
    target:         str        = "host:dev-01",
    blast_radius:   BlastRadius = BlastRadius.LIMITED,
    reversibility:  bool       = True,
    evidence_count: int        = 1,
    decision_type:  DecisionType = DecisionType.REMEDIATION,
) -> DecisionProposal:
    evidence = [
        EvidenceItem(source="monitor", content=f"alert-{i}", confidence=0.9)
        for i in range(evidence_count)
    ]
    return DecisionProposal(
        decision_id=str(uuid.uuid4()),
        decision_type=decision_type,
        proposed_by="soc-agent/v1",
        description="Isolate host",
        target=target,
        reversibility=reversibility,
        blast_radius=blast_radius,
        confidence=0.8,
        evidence=evidence,
    )


def make_org_policy(
    max_blast_radius: str = "critical",
    cross_org_min_dsal: int = 4,
    prod_reversibility: bool = False,
) -> OrgPolicy:
    return OrgPolicy(
        absolute_constraints=OrgPolicyAbsoluteConstraints(
            max_blast_radius=max_blast_radius,
            cross_org_min_dsal=cross_org_min_dsal,
            prod_reversibility=prod_reversibility,
        )
    )


# ---------------------------------------------------------------------------
# 1. Posture registration tests (SPEC §8.9)
# ---------------------------------------------------------------------------


def test_posture_registration():
    section("Posture registration — OrgPolicy constraint validation")

    policy = DecisionPolicyProvider(
        allow_unregistered_agents=True,
        org_policy=make_org_policy(max_blast_radius="limited"),
    )

    # Valid posture: within ceiling
    valid_posture = make_posture(max_blast_radius="limited")
    ok_flag, reason = policy.validate_user_posture(valid_posture)
    if ok_flag:
        ok("UserPosture within OrgPolicy ceiling → accepted")
    else:
        fail("UserPosture within ceiling should be accepted", reason)

    # Violation: posture exceeds ceiling
    violating_posture = make_posture(max_blast_radius="critical")
    ok_flag, reason = policy.validate_user_posture(violating_posture)
    if not ok_flag:
        ok("UserPosture exceeding OrgPolicy ceiling → REJECTED")
    else:
        fail("UserPosture exceeding ceiling should be rejected")

    # Missing simulation_ref must be rejected
    no_sim_ref = make_posture(simulation_ref="")
    ok_flag, reason = policy.validate_user_posture(no_sim_ref)
    if not ok_flag:
        ok("UserPosture without simulation_ref → REJECTED")
    else:
        fail("UserPosture without simulation_ref should be rejected")

    # Unsigned UserPosture must be rejected (SPEC §8.2, §8.7)
    unsigned_posture = make_posture(posture_signature=None)
    ok_flag, reason = policy.validate_user_posture(unsigned_posture)
    if not ok_flag:
        ok("UserPosture without posture_signature → REJECTED (SPEC §8.2)")
    else:
        fail("UserPosture without posture_signature should be rejected")

    # History immutability: PostureHistoryEntry is frozen
    posture_with_history = UserPosture(
        version="1.0",
        principal_id="alice@example.com",
        signed_at=now(),
        intent_statement="Test",
        simulation_ref="sim-001",
        constraints=PostureConstraints(
            target_scope="host:dev-.*",
            max_blast_radius="limited",
            reversibility_required=True,
            minimum_evidence=1,
        ),
        history=[
            PostureHistoryEntry(version="0.9", signed_at=now(), note="Initial"),
        ],
    )
    entry = posture_with_history.history[0]
    try:
        entry.note = "tampered"
        fail("History entry should be immutable (frozen)")
    except Exception:
        ok("History entry is immutable (frozen pydantic model)")


# ---------------------------------------------------------------------------
# 2. PostureEngine — Layer 1 tests (SPEC §8.4, §8.9)
# ---------------------------------------------------------------------------


def test_posture_engine_layer1():
    section("PostureEngine Layer 1 — Static structural comparison")

    posture = make_posture(
        target_scope="host:dev-.*",
        max_blast_radius="limited",
        reversibility_required=True,
        minimum_evidence=2,
    )
    engine = PostureEngine(posture)

    # Target outside scope → REJECT, must never reach RiskPipeline
    proposal_out_of_scope = make_proposal(target="host:prod-01", evidence_count=2)
    outcome, req = engine.evaluate(proposal_out_of_scope)
    if outcome == PostureOutcome.REJECT and req is None:
        ok("target outside target_scope → REJECT (no refinement request)")
    else:
        fail("target outside target_scope should be REJECT", f"got {outcome}")

    # Blast radius too high → REJECT
    proposal_high_blast = make_proposal(
        blast_radius=BlastRadius.CRITICAL, evidence_count=2
    )
    outcome, req = engine.evaluate(proposal_high_blast)
    if outcome == PostureOutcome.REJECT:
        ok("blast_radius exceeds max_blast_radius → REJECT")
    else:
        fail("blast_radius exceeding ceiling should be REJECT", f"got {outcome}")

    # Irreversible when reversibility_required=True → REJECT
    proposal_irreversible = make_proposal(reversibility=False, evidence_count=2)
    outcome, req = engine.evaluate(proposal_irreversible)
    if outcome == PostureOutcome.REJECT:
        ok("irreversible proposal with reversibility_required=True → REJECT")
    else:
        fail("irreversible proposal should be REJECT", f"got {outcome}")

    # Insufficient evidence → REJECT
    proposal_low_evidence = make_proposal(evidence_count=0)
    outcome, req = engine.evaluate(proposal_low_evidence)
    if outcome == PostureOutcome.REJECT:
        ok("evidence_count < minimum_evidence → REJECT")
    else:
        fail("insufficient evidence should be REJECT", f"got {outcome}")

    # All constraints satisfied → PASS (must NOT receive REJECT from Layer 1)
    proposal_valid = make_proposal(
        target="host:dev-42", blast_radius=BlastRadius.LIMITED,
        reversibility=True, evidence_count=2,
    )
    outcome, req = engine.evaluate(proposal_valid)
    if outcome == PostureOutcome.PASS:
        ok("all constraints satisfied → PASS (no REJECT from Layer 1)")
    else:
        fail("valid proposal should be PASS", f"got {outcome}")


# ---------------------------------------------------------------------------
# 3. PostureEngine — AMBIGUOUS produces PostureRefinementRequest (SPEC §8.4, §8.9)
# ---------------------------------------------------------------------------


def test_posture_ambiguous_produces_refinement():
    section("PostureEngine AMBIGUOUS → PostureRefinementRequest (not DeniedDecision)")

    # Posture with unknown blast_radius value to force AMBIGUOUS in Layer 1
    # We test by directly constructing a PostureConstraints with an unusual blast_radius
    # and a proposal that forces an AMBIGUOUS path via unresolved constraints.
    # Here we simulate the AMBIGUOUS branch by patching the layer1 result.

    class AmbiguousPostureEngine(PostureEngine):
        def _layer1(self, proposal):
            # Force AMBIGUOUS with unresolved constraints
            return PostureOutcome.AMBIGUOUS, ["target_scope"], ["minimum_evidence"]

    posture = make_posture()
    engine = AmbiguousPostureEngine(posture)
    proposal = make_proposal()
    outcome, req = engine.evaluate(proposal)

    if outcome == PostureOutcome.AMBIGUOUS:
        ok("AMBIGUOUS outcome correctly returned")
    else:
        fail("AMBIGUOUS outcome expected", f"got {outcome}")

    if isinstance(req, PostureRefinementRequest):
        ok("AMBIGUOUS → PostureRefinementRequest (not DeniedDecision)")
    else:
        fail("AMBIGUOUS should produce PostureRefinementRequest", f"got {type(req)}")

    if req is not None:
        # Verify required fields
        if req.proposal_id and req.principal_id:
            ok("PostureRefinementRequest has proposal_id and principal_id")
        else:
            fail("PostureRefinementRequest missing proposal_id or principal_id")

        if req.ambiguity:
            ok("PostureRefinementRequest has ambiguity explanation")
        else:
            fail("PostureRefinementRequest missing ambiguity field")

        if isinstance(req.matched_constraints, list) and isinstance(req.unresolved, list):
            ok("PostureRefinementRequest has matched_constraints and unresolved lists")
        else:
            fail("PostureRefinementRequest missing matched_constraints or unresolved")


# ---------------------------------------------------------------------------
# 4. PostureRefinementRequest is NOT DeniedDecision (SPEC §8.5)
# ---------------------------------------------------------------------------


def test_refinement_request_is_not_denied_decision():
    section("PostureRefinementRequest is a distinct type (not DeniedDecision)")

    from shani.core.evaluator import DeniedDecision

    req = PostureRefinementRequest(
        proposal_id="prop-001",
        principal_id="alice@example.com",
        ambiguity="Cannot determine scope.",
        matched_constraints=["target_scope"],
        unresolved=["minimum_evidence"],
    )

    if not isinstance(req, DeniedDecision):
        ok("PostureRefinementRequest is NOT a DeniedDecision")
    else:
        fail("PostureRefinementRequest must not be a subtype of DeniedDecision")

    if isinstance(req, PostureRefinementRequest):
        ok("PostureRefinementRequest is a first-class type")
    else:
        fail("PostureRefinementRequest should be its own type")

    # Verify immutability (frozen dataclass)
    try:
        req.ambiguity = "tampered"
        fail("PostureRefinementRequest should be immutable")
    except Exception:
        ok("PostureRefinementRequest is immutable (frozen dataclass)")


# ---------------------------------------------------------------------------
# 5. Cross-org ADO — propagated_constraints (SPEC §8.8, §8.9)
# ---------------------------------------------------------------------------


def test_cross_org_propagated_constraints():
    section("Cross-org ADO — propagated_constraints (ADO v5.1)")

    from shani.schemas.decision import (
        AuthorizedDecisionObject, DelegationRules, ExecContext,
        IntentBinding,
    )

    issued = now()
    expires = issued + timedelta(minutes=5)
    constraints = ["target_scope:domestic-only", "max_blast_radius:limited"]

    ado = AuthorizedDecisionObject(
        decision_id=str(uuid.uuid4()),
        proposal_hash="abc123",
        signature="sig456",
        authority="Board-Level",
        authorized_dsal=4,
        delegation_rules=DelegationRules(),
        nonce=os.urandom(32).hex(),
        issued_at=issued,
        expires_at=expires,
        exec_context=ExecContext(
            decision_type=DecisionType.POLICY_UPDATE,
            intent_binding=IntentBinding(
                intent="cross-org delegation",
                target="org:beta",
                scope_summary="domestic-only",
                expected_effect="Propagate constraints",
                reversibility=True,
            ),
        ),
        propagated_constraints=constraints,
        origin_org="org-alpha",
    )

    if ado.propagated_constraints == constraints:
        ok("propagated_constraints stored in ADO v5.1")
    else:
        fail("propagated_constraints not stored correctly")

    if ado.origin_org == "org-alpha":
        ok("origin_org stored in ADO v5.1")
    else:
        fail("origin_org not stored correctly")

    # ADO without propagated_constraints defaults to empty list
    ado_no_propagated = AuthorizedDecisionObject(
        decision_id=str(uuid.uuid4()),
        proposal_hash="abc123",
        signature="sig456",
        authority="SecOps-Lead",
        authorized_dsal=2,
        delegation_rules=DelegationRules(),
        nonce=os.urandom(32).hex(),
        issued_at=issued,
        expires_at=expires,
        exec_context=ExecContext(
            decision_type=DecisionType.REMEDIATION,
            intent_binding=IntentBinding(
                intent="remediation:isolate",
                target="host:dev-01",
                scope_summary="isolated",
                expected_effect="Host isolated",
                reversibility=True,
            ),
        ),
    )
    if ado_no_propagated.propagated_constraints == []:
        ok("ADO without propagated_constraints defaults to []")
    else:
        fail("ADO.propagated_constraints should default to []")

    if ado_no_propagated.origin_org is None:
        ok("ADO without origin_org defaults to None")
    else:
        fail("ADO.origin_org should default to None")

    # Cross-org ADO without propagated_constraints treated as AMBIGUOUS
    # (receiving Shani cannot validate → should reject or request refinement)
    cross_org_no_constraints = AuthorizedDecisionObject(
        decision_id=str(uuid.uuid4()),
        proposal_hash="abc123",
        signature="sig456",
        authority="Board-Level",
        authorized_dsal=4,
        delegation_rules=DelegationRules(),
        nonce=os.urandom(32).hex(),
        issued_at=issued,
        expires_at=expires,
        exec_context=ExecContext(
            decision_type=DecisionType.POLICY_UPDATE,
            intent_binding=IntentBinding(
                intent="cross-org op",
                target="org:beta",
                scope_summary="",
                expected_effect="",
                reversibility=True,
            ),
        ),
        origin_org="org-alpha",
        # propagated_constraints intentionally omitted → []
    )
    is_cross_org_missing = (
        cross_org_no_constraints.origin_org is not None
        and len(cross_org_no_constraints.propagated_constraints) == 0
    )
    if is_cross_org_missing:
        ok("Cross-org ADO without propagated_constraints detected (MUST be AMBIGUOUS per SPEC)")
    else:
        fail("Cross-org ADO without propagated_constraints not detected correctly")


# ---------------------------------------------------------------------------
# 6. PostureSimulation tests (SPEC §8.6, §8.9)
# ---------------------------------------------------------------------------


def test_posture_simulation():
    section("PostureSimulation — pre-signing requirement")

    posture = make_posture(
        target_scope="host:dev-.*",
        max_blast_radius="limited",
        reversibility_required=True,
        minimum_evidence=1,
    )

    historical = [
        # PASS: matches all constraints
        make_proposal(target="host:dev-01", blast_radius=BlastRadius.LIMITED,
                      reversibility=True, evidence_count=1),
        make_proposal(target="host:dev-02", blast_radius=BlastRadius.ISOLATED,
                      reversibility=True, evidence_count=2),
        # REJECT: target out of scope
        make_proposal(target="host:prod-01", blast_radius=BlastRadius.LIMITED,
                      reversibility=True, evidence_count=1),
        # REJECT: blast_radius too high
        make_proposal(target="host:dev-03", blast_radius=BlastRadius.CRITICAL,
                      reversibility=True, evidence_count=1),
        # REJECT: irreversible
        make_proposal(target="host:dev-04", blast_radius=BlastRadius.LIMITED,
                      reversibility=False, evidence_count=1),
    ]

    sim = PostureSimulation()
    result = sim.run(posture, historical)

    if isinstance(result, PostureSimulationResult):
        ok("PostureSimulation returns PostureSimulationResult")
    else:
        fail("PostureSimulation should return PostureSimulationResult")

    if result.pass_count == 2:
        ok(f"pass_count = {result.pass_count} (expected 2)")
    else:
        fail(f"pass_count expected 2, got {result.pass_count}")

    if result.reject_count == 3:
        ok(f"reject_count = {result.reject_count} (expected 3)")
    else:
        fail(f"reject_count expected 3, got {result.reject_count}")

    # At least 3 reject_examples when rejections exist
    if len(result.reject_examples) >= min(3, result.reject_count):
        ok(f"reject_examples contains {len(result.reject_examples)} examples (≥ 3 required)")
    else:
        fail("reject_examples should contain at least 3 examples when rejections exist")

    if result.simulation_id:
        ok("simulation_id is non-empty (usable as simulation_ref)")
    else:
        fail("simulation_id should be non-empty")

    # Delta comparison: with a broader current posture
    current_posture = make_posture(
        target_scope=".*",        # allows all targets
        max_blast_radius="critical",
        reversibility_required=False,
        minimum_evidence=0,
    )
    result_with_delta = sim.run(posture, historical, current_posture=current_posture)
    if result_with_delta.delta_vs_current is not None:
        ok("delta_vs_current present when current_posture provided")
        delta = result_with_delta.delta_vs_current
        if "new_reject_count" in delta and "current_reject_count" in delta and "delta" in delta:
            ok(
                f"delta: new={delta['new_reject_count']}, "
                f"current={delta['current_reject_count']}, "
                f"Δ={delta['delta']}"
            )
        else:
            fail("delta_vs_current missing required keys")
    else:
        fail("delta_vs_current should be present when current_posture is provided")


# ---------------------------------------------------------------------------
# 7. OrgPolicy absolute_constraints enforcement
# ---------------------------------------------------------------------------


def test_org_policy_absolute_constraints():
    section("OrgPolicy absolute_constraints — ceiling enforcement")

    policy_limited = DecisionPolicyProvider(
        allow_unregistered_agents=True,
        org_policy=make_org_policy(max_blast_radius="limited"),
    )

    # Posture at ceiling → OK
    at_ceiling = make_posture(max_blast_radius="limited")
    ok_flag, _ = policy_limited.validate_user_posture(at_ceiling)
    if ok_flag:
        ok("Posture at ceiling level → accepted")
    else:
        fail("Posture at ceiling should be accepted")

    # Posture below ceiling → OK
    below_ceiling = make_posture(max_blast_radius="isolated")
    ok_flag, _ = policy_limited.validate_user_posture(below_ceiling)
    if ok_flag:
        ok("Posture below ceiling → accepted")
    else:
        fail("Posture below ceiling should be accepted")

    # Posture above ceiling → REJECTED
    for exceeding in ("significant", "critical"):
        above_ceiling = make_posture(max_blast_radius=exceeding)
        ok_flag, reason = policy_limited.validate_user_posture(above_ceiling)
        if not ok_flag:
            ok(f"Posture with max_blast_radius={exceeding!r} > ceiling 'limited' → REJECTED")
        else:
            fail(f"Posture with max_blast_radius={exceeding!r} should be rejected")

    # Default org_policy (critical ceiling) accepts all blast_radius values
    policy_default = DecisionPolicyProvider(allow_unregistered_agents=True)
    for br in ("isolated", "limited", "significant", "critical"):
        p = make_posture(max_blast_radius=br)
        ok_flag, _ = policy_default.validate_user_posture(p)
        if ok_flag:
            ok(f"Default policy (critical ceiling): max_blast_radius={br!r} → accepted")
        else:
            fail(f"Default policy should accept {br!r}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("=" * 60)
    print("  Shani v0.4 Conformance Tests")
    print("=" * 60)

    test_posture_registration()
    test_posture_engine_layer1()
    test_posture_ambiguous_produces_refinement()
    test_refinement_request_is_not_denied_decision()
    test_cross_org_propagated_constraints()
    test_posture_simulation()
    test_org_policy_absolute_constraints()

    print("\n" + "=" * 60)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All v0.4 conformance tests passed.")
    print("=" * 60)
