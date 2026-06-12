"""
tests/security/test_enforcer_negative.py

Enforcer Negative Tests — verify that invalid ADOs are correctly blocked.

PR review feedback: "「不正な署名を持つADOをエージェントが提示した際、
Enforcerが正しくブロックするか」というネガティブテスト"

Tests:
    ① verify_binding() returns False for ADO with tampered signature
    ② verify_binding() returns False for ADO with tampered decision_id
    ③ verify_binding() returns False for ADO with tampered authorized_dsal (escalation)
    ④ verify_binding() returns False for ADO with tampered authority
    ⑤ verify_binding() returns False for expired ADO
    ⑥ issue_capability() raises CapabilityError for ADO with invalid signature
    ⑦ issue_capability() raises for expired ADO (caught in verify_binding)
    ⑧ Pipeline fail-safe: evaluate() returns DeniedDecision when pipeline raises
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

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

from shani import ShaniEvaluator, DeniedDecision, StaticAuthorityProvider, DecisionType, BlastRadius
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg: str) -> None:
    print(f"  {PASS} {msg}")


def fail(msg: str, detail: str = "") -> None:
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n  ── {title}")


def future(hours: int = 1) -> datetime:
    return datetime.now(tz=timezone.utc) + timedelta(hours=hours)


def past(seconds: int = 1) -> datetime:
    return datetime.now(tz=timezone.utc) - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_evaluator():
    agents = {
        "agent/v1": AgentIdentity(
            agent_id="agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(["remediation", "data_access"]),
        )
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )


def make_proposal(**kwargs):
    defaults = dict(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="agent/v1",
        description="Restart nginx after CPU alert on dev host",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="CPU 99%", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=future(),
    )
    defaults.update(kwargs)
    return DecisionProposal(**defaults)


# ---------------------------------------------------------------------------
# ① Tampered signature → verify_binding returns False
# ---------------------------------------------------------------------------

def test_tampered_signature_blocked():
    section("① Tampered signature → verify_binding() = False")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    assert ev.verify_binding(ado, proposal), "Valid ADO must pass verify_binding"
    ok("Baseline: valid ADO passes verify_binding()")

    # Tamper the signature
    tampered = ado.model_copy(update={"signature": "deadbeef" * 16})
    result = ev.verify_binding(tampered, proposal)
    if result:
        fail("SECURITY GAP: tampered signature passed verify_binding()")
    else:
        ok("Tampered signature → verify_binding() returns False ✓")


# ---------------------------------------------------------------------------
# ② Tampered decision_id → verify_binding returns False
# ---------------------------------------------------------------------------

def test_tampered_decision_id_blocked():
    section("② Tampered decision_id → verify_binding() = False")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    tampered = ado.model_copy(update={"decision_id": "evil-decision-id"})
    result = ev.verify_binding(tampered, proposal)
    if result:
        fail("SECURITY GAP: tampered decision_id passed verify_binding()")
    else:
        ok("Tampered decision_id → verify_binding() returns False ✓")


# ---------------------------------------------------------------------------
# ③ Tampered authorized_dsal (escalation attack) → verify_binding returns False
# ---------------------------------------------------------------------------

def test_tampered_dsal_escalation_blocked():
    section("③ D-SAL escalation attack → verify_binding() = False")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    original_dsal = ado.authorized_dsal
    escalated = ado.model_copy(update={"authorized_dsal": min(4, original_dsal + 2)})
    result = ev.verify_binding(escalated, proposal)
    if result:
        fail(f"SECURITY GAP: D-SAL escalation ({original_dsal}→{escalated.authorized_dsal}) passed verify_binding()")
    else:
        ok(f"D-SAL escalation ({original_dsal}→{escalated.authorized_dsal}) → verify_binding() = False ✓")


# ---------------------------------------------------------------------------
# ④ Tampered authority → verify_binding returns False
# ---------------------------------------------------------------------------

def test_tampered_authority_blocked():
    section("④ Tampered authority → verify_binding() = False")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    tampered = ado.model_copy(update={"authority": "Attacker-Authority"})
    result = ev.verify_binding(tampered, proposal)
    if result:
        fail("SECURITY GAP: tampered authority passed verify_binding()")
    else:
        ok("Tampered authority → verify_binding() returns False ✓")


# ---------------------------------------------------------------------------
# ⑤ Expired ADO → verify_binding returns False
# ---------------------------------------------------------------------------

def test_expired_ado_blocked_by_verify_binding():
    section("⑤ Expired ADO → verify_binding() = False")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    assert ev.verify_binding(ado, proposal), "Valid ADO must pass verify_binding"
    ok("Baseline: fresh ADO passes verify_binding()")

    # Simulate an expired ADO by backdating both issued_at and expires_at.
    # expires_at must remain > issued_at to pass the model_validator.
    expired_issued = past(seconds=120)
    expired_expires = past(seconds=60)

    expired_ado = ado.model_construct(
        decision_id=ado.decision_id,
        proposal_hash=ado.proposal_hash,
        signature=ado.signature,
        authority=ado.authority,
        authorized_dsal=ado.authorized_dsal,
        delegation_rules=ado.delegation_rules,
        nonce=ado.nonce,
        issued_at=expired_issued,
        expires_at=expired_expires,
        exec_context=ado.exec_context,
    )

    if not expired_ado.is_expired():
        fail("Test setup error: ADO should be expired")
        return

    result = ev.verify_binding(expired_ado, proposal)
    if result:
        fail("SECURITY GAP: expired ADO passed verify_binding()")
    else:
        ok("Expired ADO → verify_binding() returns False ✓")


# ---------------------------------------------------------------------------
# ⑥ issue_capability() raises CapabilityError for invalid signature
# ---------------------------------------------------------------------------

def test_issue_capability_blocks_invalid_signature():
    section("⑥ issue_capability() raises CapabilityError for invalid signature")

    from shani.boundary.capability import ExecutionBoundary, CapabilityError

    ev = make_evaluator()
    boundary = ExecutionBoundary(ev)

    proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
    )
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    # Tamper the signature
    tampered = ado.model_copy(update={"signature": "cafebabe" * 16})

    try:
        boundary.issue_capability(tampered, proposal)
        fail("SECURITY GAP: issue_capability issued a Capability for tampered ADO")
    except CapabilityError as e:
        ok(f"issue_capability raises CapabilityError for tampered ADO ✓: {str(e)[:60]}")
    except Exception as e:
        fail(f"Unexpected exception type: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# ⑦ issue_capability() raises for expired ADO
# ---------------------------------------------------------------------------

def test_issue_capability_blocks_expired_ado():
    section("⑦ issue_capability() raises for expired ADO")

    from shani.boundary.capability import ExecutionBoundary, CapabilityError, CapabilityExpired

    ev = make_evaluator()
    boundary = ExecutionBoundary(ev)

    proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        target="host:dev-01",
    )
    ado = ev.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        fail("Proposal was unexpectedly denied", ado.reason)
        return

    # Simulate expiry via model_construct
    expired_ado = ado.model_construct(
        decision_id=ado.decision_id,
        proposal_hash=ado.proposal_hash,
        signature=ado.signature,
        authority=ado.authority,
        authorized_dsal=ado.authorized_dsal,
        delegation_rules=ado.delegation_rules,
        nonce=ado.nonce,
        issued_at=past(seconds=120),
        expires_at=past(seconds=60),
        exec_context=ado.exec_context,
    )

    try:
        boundary.issue_capability(expired_ado, proposal)
        fail("SECURITY GAP: issue_capability issued a Capability for expired ADO")
    except (CapabilityError, CapabilityExpired) as e:
        ok(f"issue_capability raises for expired ADO ✓: {type(e).__name__}: {str(e)[:60]}")
    except Exception as e:
        fail(f"Unexpected exception type: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# ⑧ Pipeline fail-safe: evaluate() returns DeniedDecision when pipeline raises
# ---------------------------------------------------------------------------

def test_pipeline_failure_triggers_fail_safe():
    section("⑧ Pipeline failure → evaluate() returns DeniedDecision (fail-safe)")

    from shani.risk.pipeline import RiskPipeline

    class FailingPipeline(RiskPipeline):
        def evaluate(self, *args, **kwargs):
            raise RuntimeError("LLM timeout / parse error simulation")

    ev = make_evaluator()
    # Inject the failing pipeline
    ev._risk_pipeline = FailingPipeline()

    proposal = make_proposal()
    result = ev.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        ok(f"Pipeline failure → DeniedDecision (fail-safe) ✓: {result.reason[:60]}")
    else:
        fail("SECURITY GAP: pipeline failure did not trigger fail-safe denial")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 62)
    print("  Enforcer Negative Tests — invalid ADOs must be blocked")
    print("=" * 62)

    test_tampered_signature_blocked()
    test_tampered_decision_id_blocked()
    test_tampered_dsal_escalation_blocked()
    test_tampered_authority_blocked()
    test_expired_ado_blocked_by_verify_binding()
    test_issue_capability_blocks_invalid_signature()
    test_issue_capability_blocks_expired_ado()
    test_pipeline_failure_triggers_fail_safe()

    print("\n" + "=" * 62)
    if _failures:
        print(f"  FAILED: {len(_failures)} test(s)")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All enforcer negative tests passed.")
        print()
        print("  Security guarantees verified:")
        print("    ① Tampered signature → blocked by verify_binding()")
        print("    ② Tampered decision_id → blocked by verify_binding()")
        print("    ③ D-SAL escalation → blocked by verify_binding()")
        print("    ④ Tampered authority → blocked by verify_binding()")
        print("    ⑤ Expired ADO → blocked by verify_binding()")
        print("    ⑥ Invalid signature → CapabilityError from issue_capability()")
        print("    ⑦ Expired ADO → CapabilityError/Expired from issue_capability()")
        print("    ⑧ Pipeline failure → fail-safe DeniedDecision")
    print("=" * 62)
