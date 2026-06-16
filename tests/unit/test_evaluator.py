"""
tests/unit/test_evaluator.py

ShaniEvaluator unit tests — v0.3.

Design changes from v0.1:
  - No requested_dsal (removed; Shani computes effective D-SAL from context)
  - No pytest dependency (stdlib only)
  - Tests reflect RiskPipeline-based evaluation
  - Tests cover DenialContext propagation
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
from shani.schemas.decision import (
    DecisionProposal,
    DecisionScope,
    EvidenceItem,
)
from shani.integrity.monitor import IntegritySignal, IntegritySignalType

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


def future(h=1):
    return datetime.now(tz=timezone.utc) + timedelta(hours=h)


def make_agent(
    agent_id="test-agent/v1",
    granted_dsal=3,
    types=("remediation", "configuration_change", "network_action", "data_access"),
):
    return AgentIdentity(
        agent_id=agent_id, granted_dsal=granted_dsal, allowed_decision_types=frozenset(types)
    )


def make_evaluator(max_dsal=3, kill_switch=False, dis=None, agents=None):
    if agents is None:
        agents = {"test-agent/v1": make_agent()}
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=max_dsal),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
        kill_switch=kill_switch,
        dis_machine=dis,
    )


def make_proposal(
    decision_type=DecisionType.REMEDIATION,
    target="host:dev-01",
    blast_radius=BlastRadius.LIMITED,
    reversibility=True,
    confidence=0.9,
    delegation=False,
    evidence=None,
    description="Restart nginx after high CPU alert",
    expires_at=None,
):
    if evidence is None:
        evidence = [EvidenceItem(source="monitor", content="CPU 99%", confidence=0.9)]
    return DecisionProposal(
        decision_type=decision_type,
        proposed_by="test-agent/v1",
        description=description,
        target=target,
        scope=DecisionScope(asset_ids=[target]),
        evidence=evidence,
        confidence=confidence,
        reversibility=reversibility,
        blast_radius=blast_radius,
        delegation=delegation,
        expires_at=expires_at or future(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Happy path
# ─────────────────────────────────────────────────────────────────────────────


def test_authorized_low_risk():
    section("Happy path — low risk proposal is authorized")
    ev = make_evaluator()
    result = ev.evaluate(make_proposal())
    assert not isinstance(result, DeniedDecision), f"Unexpected denial: {result}"
    assert result.authorized_dsal >= 1
    ok(f"ADO issued | dsal={result.authorized_dsal}")
    assert result.proposal_hash
    ok("proposal_hash present")
    assert result.nonce and len(result.nonce) == 64
    ok("nonce is 64-char hex")
    assert result.signature
    ok("signature present")


def test_verify_binding_passes_on_valid_ado():
    section("verify_binding returns True for fresh ADO")
    ev = make_evaluator()
    p = make_proposal()
    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)
    assert ev.verify_binding(ado, p)
    ok("verify_binding(ado, proposal) = True")


def test_replay_blocked_after_register_executed():
    section("Replay blocked after register_executed")
    ev = make_evaluator()
    p = make_proposal()
    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)
    assert ev.verify_binding(ado, p)
    ev.register_executed(ado)
    assert not ev.verify_binding(ado, p)
    ok("verify_binding returns False after nonce consumed")


def test_fake_ado_rejected_by_proposal_hash():
    section("Fake ADO (different proposal) rejected")
    ev = make_evaluator()
    p1 = make_proposal(target="host:dev-01")
    p2 = make_proposal(target="host:prod-db-99")
    ado = ev.evaluate(p1)
    assert not isinstance(ado, DeniedDecision)
    # Verify with wrong proposal — proposal_hash mismatch
    assert not ev.verify_binding(ado, p2)
    ok("verify_binding(ado, wrong_proposal) = False (fake ADO rejected)")


# ─────────────────────────────────────────────────────────────────────────────
# Denial paths
# ─────────────────────────────────────────────────────────────────────────────


def test_kill_switch_denies_all():
    section("Kill switch denies all proposals")
    ev = make_evaluator(kill_switch=True)
    result = ev.evaluate(make_proposal())
    assert isinstance(result, DeniedDecision)
    assert "kill" in result.reason.lower() or "switch" in result.reason.lower()
    ok(f"Kill switch denial: {result.reason}")


def test_dis_violated_denies_all():
    section("DIS=VIOLATED denies all proposals")
    dis = DISStateMachine()
    ev = make_evaluator(dis=dis)
    ev.process_integrity_signal(
        IntegritySignal(
            signal_type=IntegritySignalType.AGENT_IDENTITY_DRIFT,
            source="test",
            decision_id="dec-000",
            detail="identity drift detected",
        )
    )
    assert dis.state == DIS.VIOLATED
    result = ev.evaluate(make_proposal())
    assert isinstance(result, DeniedDecision)
    ok(f"DIS=VIOLATED denial: {result.reason[:50]}")


def test_expired_proposal_denied():
    section("Expired proposal denied")
    ev = make_evaluator()
    # Use model_construct to bypass the future-only validator,
    # simulating a proposal that was valid when created but has since expired.
    from shani.schemas.decision import DecisionScope, EvidenceItem

    p = DecisionProposal.model_construct(
        decision_id=__import__("uuid").uuid4().hex,
        decision_type=DecisionType.REMEDIATION,
        proposed_by="test-agent/v1",
        description="Test expired proposal",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="test", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=datetime.now(tz=timezone.utc) - timedelta(seconds=1),
    )
    result = ev.evaluate(p)
    assert isinstance(result, DeniedDecision)
    assert "expir" in result.reason.lower()
    ok(f"Expired proposal denied: {result.reason}")


def test_unregistered_agent_denied():
    section("Unregistered agent denied")
    ev = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(allow_unregistered_agents=False),
    )
    p = make_proposal()
    result = ev.evaluate(p)
    assert isinstance(result, DeniedDecision)
    assert "not registered" in result.reason.lower() or "agent" in result.reason.lower()
    ok(f"Unregistered agent denied: {result.reason[:50]}")


def test_decision_type_not_allowed_denied():
    section("DecisionType not in agent's allowed list is denied")
    agents = {"test-agent/v1": make_agent(types=("data_access",))}  # only data_access
    ev = make_evaluator(agents=agents)
    p = make_proposal(decision_type=DecisionType.NETWORK_ACTION)  # not allowed
    result = ev.evaluate(p)
    assert isinstance(result, DeniedDecision)
    ok(f"Wrong decision_type denied: {result.reason[:60]}")


def test_agent_granted_dsal_too_low():
    section("Agent granted_dsal too low for high-risk proposal")
    # Agent only has D-SAL 1 but proposal is high-risk (prod + critical)
    agents = {"test-agent/v1": make_agent(granted_dsal=1)}
    ev = make_evaluator(agents=agents)
    p = make_proposal(
        target="host:prod-critical",
        blast_radius=BlastRadius.CRITICAL,
        reversibility=False,
        evidence=[EvidenceItem(source="edr", content="alert", confidence=0.9)],
    )
    result = ev.evaluate(p)
    assert isinstance(result, DeniedDecision)
    ok(f"granted_dsal=1 vs high-risk → denied: {result.reason[:60]}")


def test_hard_rule_critical_irreversible():
    section("RuleEngine: CRITICAL + irreversible → OVERRIDE D-SAL=4 or DENY")
    ev = make_evaluator(max_dsal=4)
    p = make_proposal(
        blast_radius=BlastRadius.CRITICAL,
        reversibility=False,
        evidence=[EvidenceItem(source="edr", content="confirmed", confidence=0.9)],
    )
    result = ev.evaluate(p)
    # Either DENIED (agent can't handle D-SAL 4) or ADO with dsal=4
    if isinstance(result, DeniedDecision):
        ok(f"CRITICAL+irreversible → denied (D-SAL 4 required, agent insufficient)")
    else:
        assert result.authorized_dsal == 4
        ok(f"CRITICAL+irreversible → authorized at D-SAL 4")


def test_evidence_required_for_high_effective_dsal():
    section("Evidence required when effective D-SAL >= 2")
    # prod target raises D-SAL → evidence required
    ev = make_evaluator()
    p = make_proposal(
        target="host:prod-critical",
        blast_radius=BlastRadius.SIGNIFICANT,
        evidence=[],  # no evidence
    )
    result = ev.evaluate(p)
    assert isinstance(result, DeniedDecision)
    assert "evidence" in result.reason.lower()
    ok(f"No evidence for high-risk → denied: {result.reason[:60]}")


# ─────────────────────────────────────────────────────────────────────────────
# DenialContext
# ─────────────────────────────────────────────────────────────────────────────


def test_denial_context_is_populated():
    section("DeniedDecision carries pipeline_result + proposal")
    ev = make_evaluator()
    p = make_proposal(blast_radius=BlastRadius.CRITICAL, evidence=[])
    result = ev.evaluate(p)
    assert isinstance(result, DeniedDecision)
    # Context should be populated
    summary = result.to_human_summary()
    assert "reason" in summary
    ok(f"to_human_summary() has 'reason': {summary['reason'][:50]}")
    if result.pipeline_result:
        assert "risk_score" in summary
        ok(f"risk_score: {summary.get('risk_score')}")
    if result.proposal:
        assert "proposal" in summary
        ok("proposal snapshot present in summary")


# ─────────────────────────────────────────────────────────────────────────────
# D-SAL computed from context (not declared by agent)
# ─────────────────────────────────────────────────────────────────────────────


def test_effective_dsal_increases_with_risk():
    section("effective_dsal increases with proposal risk")
    ev = make_evaluator(max_dsal=4)

    # Low risk
    low_risk = make_proposal(
        target="host:dev-01",
        blast_radius=BlastRadius.ISOLATED,
        reversibility=True,
        evidence=[EvidenceItem(source="monitor", content="ok", confidence=0.95)],
    )
    low_result = ev.evaluate(low_risk)
    low_dsal = low_result.authorized_dsal if not isinstance(low_result, DeniedDecision) else 99
    ok(f"Low risk: effective_dsal={low_dsal}")

    # High risk
    agents = {"test-agent/v1": make_agent(granted_dsal=4)}
    ev_high = make_evaluator(max_dsal=4, agents=agents)
    high_risk = make_proposal(
        target="host:prod-critical",
        blast_radius=BlastRadius.SIGNIFICANT,
        reversibility=False,
        evidence=[EvidenceItem(source="edr", content="alert", confidence=0.85)],
    )
    high_result = ev_high.evaluate(high_risk)
    high_dsal = high_result.authorized_dsal if not isinstance(high_result, DeniedDecision) else 99
    ok(f"High risk: effective_dsal={high_dsal}")

    if low_dsal < 99 and high_dsal < 99:
        assert high_dsal >= low_dsal, f"Expected high_dsal ({high_dsal}) >= low_dsal ({low_dsal})"
        ok("High-risk proposal gets higher effective_dsal than low-risk")


def test_agent_cannot_declare_dsal():
    section("DecisionProposal has no requested_dsal field")
    import inspect
    from shani.schemas.decision import DecisionProposal

    fields = (
        DecisionProposal.__annotations__ if hasattr(DecisionProposal, "__annotations__") else {}
    )
    # Check neither via annotations nor as a settable attribute
    p = make_proposal()
    assert not hasattr(p, "requested_dsal"), "requested_dsal should not exist"
    ok("DecisionProposal has no requested_dsal attribute")
    if "requested_dsal" not in fields:
        ok("requested_dsal not in DecisionProposal annotations")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


def test_capability_is_single_use():
    section("Capability is single-use (ADO one-time guarantee)")
    from shani.boundary.capability import ExecutionBoundary, CapabilityExhausted
    from shani.schemas.decision import DecisionScope, EvidenceItem

    agents = {"test-agent/v1": make_agent()}
    ev = make_evaluator(agents=agents)
    boundary = ExecutionBoundary(ev)

    p = DecisionProposal(
        decision_type=DecisionType.DATA_ACCESS,
        proposed_by="test-agent/v1",
        description="Read monitoring data from external API endpoint for analysis",
        target="https://api.example.com/data",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="check", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.ISOLATED,
        expires_at=future(),
    )

    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)
    cap = boundary.issue_capability(ado, p)

    # First call: success
    import sys, io

    result = cap.http_get("https://api.example.com/data")
    assert result["status"] == 200
    ok("First http_get: success ✓")

    # Second call: CapabilityExhausted
    try:
        cap.http_get("https://api.example.com/data")
        fail("Second call succeeded (Capability is not single-use — bug)")
    except CapabilityExhausted as e:
        ok(f"Second call: CapabilityExhausted ✓  {str(e)[:50]}")

    # Retry issue_capability with the same ADO → rejected because nonce is consumed
    try:
        cap2 = boundary.issue_capability(ado, p)
        fail("A second Capability was issued from the same ADO (nonce reuse — bug)")
    except Exception as e:
        ok(f"ADO reuse: {type(e).__name__} ✓ (nonce consumed)")

    # new proposal → new ADO → new cap → usable
    p2 = DecisionProposal(
        decision_type=DecisionType.DATA_ACCESS,
        proposed_by="test-agent/v1",
        description="Read monitoring data from external API endpoint for analysis",
        target="https://api.example.com/data",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="check", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.ISOLATED,
        expires_at=future(),
    )
    ado2 = ev.evaluate(p2)
    assert not isinstance(ado2, DeniedDecision)
    cap3 = boundary.issue_capability(ado2, p2)
    result2 = cap3.http_get("https://api.example.com/data")
    assert result2["status"] == 200
    ok("New proposal → new ADO → new cap: success ✓")
    ok("ADO one-time guarantee: each proposal requires its own ADO and Capability")


def test_capability_thread_safe_single_use():
    section("Capability is single-use even under concurrent access")
    from shani.boundary.capability import ExecutionBoundary, CapabilityExhausted
    from shani.schemas.decision import DecisionScope, EvidenceItem
    import threading

    agents = {"test-agent/v1": make_agent()}
    ev = make_evaluator(agents=agents)
    boundary = ExecutionBoundary(ev)

    p = DecisionProposal(
        decision_type=DecisionType.DATA_ACCESS,
        proposed_by="test-agent/v1",
        description="Read monitoring data from external API endpoint for analysis",
        target="https://api.example.com/data",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="check", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.ISOLATED,
        expires_at=future(),
    )
    ado = ev.evaluate(p)
    assert not isinstance(ado, DeniedDecision)
    cap = boundary.issue_capability(ado, p)

    results = []
    errors = []

    def try_use():
        try:
            cap.http_get("https://api.example.com/data")
            results.append("success")
        except CapabilityExhausted:
            errors.append("exhausted")
        except Exception as e:
            errors.append(f"other:{e}")

    threads = [threading.Thread(target=try_use) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"Expected exactly 1 success, got {len(results)}: {results}"
    assert len(errors) == 9, f"Expected 9 exhausted, got {len(errors)}: {errors}"
    ok(f"10 concurrent threads: 1 success / {len(errors)} blocked ✓ (thread-safe)")


if __name__ == "__main__":
    print("=" * 58)
    print("  ShaniEvaluator Unit Tests — v0.3")
    print("=" * 58)

    test_authorized_low_risk()
    test_verify_binding_passes_on_valid_ado()
    test_replay_blocked_after_register_executed()
    test_fake_ado_rejected_by_proposal_hash()

    test_kill_switch_denies_all()
    test_dis_violated_denies_all()
    test_expired_proposal_denied()
    test_unregistered_agent_denied()
    test_decision_type_not_allowed_denied()
    test_agent_granted_dsal_too_low()
    test_hard_rule_critical_irreversible()
    test_evidence_required_for_high_effective_dsal()

    test_denial_context_is_populated()
    test_effective_dsal_increases_with_risk()
    test_agent_cannot_declare_dsal()
    test_capability_is_single_use()
    test_capability_thread_safe_single_use()

    print("\n" + "=" * 58)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print(f"  All {len([f for f in dir() if f.startswith('test_')])} tests passed.")
    print("=" * 58)
