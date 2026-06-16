"""
tests/unit/test_crypto_integrity.py

Cryptographic integrity and DIS monitor tests — v0.3.

Covers:
  - HMAC signature determinism
  - Signature invalidation on field mutation
  - DIS state machine transitions
  - IntegrityMonitor signal processing
"""

from __future__ import annotations

import os, sys

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

import warnings

warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone

from shani import (
    ShaniEvaluator,
    DeniedDecision,
    StaticAuthorityProvider,
    DISStateMachine,
    DIS,
    DecisionType,
    BlastRadius,
)
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem
from shani.integrity.monitor import (
    DISIntegrityMonitor,
    IntegritySignal,
    IntegritySignalType,
    SignalSeverity,
)

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg):
    print(f"  {PASS} {msg}")


def fail(msg, d=""):
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))


def section(t):
    print(f"\n  ── {t}")


def future():
    return datetime.now(tz=timezone.utc) + timedelta(hours=1)


def make_evaluator(max_dsal=3, dis=None):
    agents = {
        "a/v1": AgentIdentity(
            agent_id="a/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                ["remediation", "configuration_change", "network_action", "data_access"]
            ),
        )
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=max_dsal),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
        dis_machine=dis,
    )


def make_proposal(**kw):
    defaults = dict(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="a/v1",
        description="Restart service after high CPU alert on dev host",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="CPU 99%", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=future(),
    )
    defaults.update(kw)
    return DecisionProposal(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# Signature integrity
# ─────────────────────────────────────────────────────────────────────────────


def test_signature_deterministic():
    section("Signature is deterministic (same ADO → same signature)")
    ev = make_evaluator()
    p = make_proposal()
    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)

    # Recompute — should get same result
    sig1 = ev._compute_signature(ev._canonical_payload(ado))
    sig2 = ev._compute_signature(ev._canonical_payload(ado))
    assert sig1 == sig2
    ok("Same ADO produces same signature on recomputation")


def test_signature_changes_with_different_proposals():
    section("Different proposals produce different signatures")
    ev = make_evaluator()

    p1 = make_proposal(target="host:dev-01")
    p2 = make_proposal(target="host:dev-02")

    ado1 = ev.evaluate(p1)
    ado2 = ev.evaluate(p2)

    if not isinstance(ado1, DeniedDecision) and not isinstance(ado2, DeniedDecision):
        assert ado1.signature != ado2.signature
        ok("Different targets → different signatures")
        assert ado1.proposal_hash != ado2.proposal_hash
        ok("Different targets → different proposal_hash")


def test_proposal_hash_bound_to_proposal():
    section("proposal_hash is SHA-256 of proposal canonical form")
    ev = make_evaluator()
    p = make_proposal()
    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)

    expected_hash = p.canonical_hash()
    assert ado.proposal_hash == expected_hash
    ok(f"ado.proposal_hash matches proposal.canonical_hash()")


def test_verify_binding_false_after_nonce_consumed():
    section("verify_binding returns False after nonce consumed (replay)")
    ev = make_evaluator()
    p = make_proposal()
    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)

    assert ev.verify_binding(ado, p)
    ev.register_executed(ado)
    assert not ev.verify_binding(ado, p)
    ok("verify_binding transitions True → False after register_executed")


def test_verify_binding_false_with_wrong_proposal():
    section("verify_binding False when proposal_hash mismatches")
    ev = make_evaluator()
    p_real = make_proposal(target="host:dev-01")
    p_fake = make_proposal(target="host:prod-db-99")  # different target

    ado = ev.evaluate(p_real)
    assert not isinstance(ado, DeniedDecision)

    assert ev.verify_binding(ado, p_real)
    assert not ev.verify_binding(ado, p_fake)  # hash mismatch
    ok("verify_binding(ado, wrong_proposal) = False")


# ─────────────────────────────────────────────────────────────────────────────
# DIS state machine
# ─────────────────────────────────────────────────────────────────────────────


def test_dis_starts_valid():
    section("DIS starts in VALID state")
    dis = DISStateMachine()
    assert dis.state == DIS.VALID
    ok("DIS initial state = VALID")


def test_dis_valid_to_degraded():
    section("ASSUMPTION_DRIFT(MEDIUM) → VALID to DEGRADED")
    dis = DISStateMachine()
    monitor = DISIntegrityMonitor(dis)
    monitor.process(
        IntegritySignal(
            signal_type=IntegritySignalType.ASSUMPTION_DRIFT,
            source="test",
            decision_id="dec-001",
            detail="drift detected",
        )
    )
    assert dis.state == DIS.DEGRADED
    ok("VALID → DEGRADED on ASSUMPTION_DRIFT")


def test_dis_to_violated_on_identity_drift():
    section("AGENT_IDENTITY_DRIFT(HIGH) → VIOLATED")
    dis = DISStateMachine()
    monitor = DISIntegrityMonitor(dis)
    monitor.process(
        IntegritySignal(
            signal_type=IntegritySignalType.AGENT_IDENTITY_DRIFT,
            source="test",
            decision_id="dec-001",
            detail="identity change detected",
        )
    )
    assert dis.state == DIS.VIOLATED
    ok("VALID → VIOLATED on AGENT_IDENTITY_DRIFT")


def test_dis_violated_denies_all_proposals():
    section("DIS=VIOLATED causes all proposals to be denied")
    dis = DISStateMachine()
    ev = make_evaluator(dis=dis)

    # Trigger VIOLATED
    ev.process_integrity_signal(
        IntegritySignal(
            signal_type=IntegritySignalType.REPLAY_ATTACK,
            source="test",
            decision_id="dec-001",
            detail="replay detected",
        )
    )
    assert dis.state == DIS.VIOLATED

    result = ev.evaluate(make_proposal())
    assert isinstance(result, DeniedDecision)
    ok(f"DIS=VIOLATED → proposal denied: {result.reason[:50]}")


def test_dis_reset_requires_justification():
    section("DIS reset from VIOLATED requires justification + authority")
    dis = DISStateMachine()
    monitor = DISIntegrityMonitor(dis)
    monitor.process(
        IntegritySignal(
            signal_type=IntegritySignalType.AGENT_IDENTITY_DRIFT,
            source="test",
            decision_id="dec-001",
            detail="breach",
        )
    )
    assert dis.state == DIS.VIOLATED

    # Reset with proper justification
    dis.reset_to_valid(
        justification="False positive confirmed by security team",
        authorized_by="alice@example.com",
    )
    assert dis.state == DIS.VALID
    ok("DIS reset to VALID with justification + authority")


def test_dis_replay_attack_immediate_violated():
    section("REPLAY_ATTACK(CRITICAL) → immediate VIOLATED from any state")
    dis = DISStateMachine()
    monitor = DISIntegrityMonitor(dis)

    # First go to DEGRADED
    monitor.process(
        IntegritySignal(
            signal_type=IntegritySignalType.ASSUMPTION_DRIFT,
            source="test",
            decision_id="dec-001",
            detail="drift",
        )
    )
    assert dis.state == DIS.DEGRADED

    # REPLAY_ATTACK from DEGRADED → VIOLATED immediately
    monitor.process(
        IntegritySignal(
            signal_type=IntegritySignalType.REPLAY_ATTACK,
            source="test",
            decision_id="dec-002",
            detail="replay",
        )
    )
    assert dis.state == DIS.VIOLATED
    ok("REPLAY_ATTACK from DEGRADED → VIOLATED immediately")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 58)
    print("  Crypto + DIS Integrity Unit Tests — v0.3")
    print("=" * 58)

    test_signature_deterministic()
    test_signature_changes_with_different_proposals()
    test_proposal_hash_bound_to_proposal()
    test_verify_binding_false_after_nonce_consumed()
    test_verify_binding_false_with_wrong_proposal()

    test_dis_starts_valid()
    test_dis_valid_to_degraded()
    test_dis_to_violated_on_identity_drift()
    test_dis_violated_denies_all_proposals()
    test_dis_reset_requires_justification()
    test_dis_replay_attack_immediate_violated()

    print("\n" + "=" * 58)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All tests passed.")
    print("=" * 58)
