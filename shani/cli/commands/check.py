"""shani check — Quick end-to-end ADO issuance and replay-prevention check."""

from __future__ import annotations

import sys


def cmd_check() -> int:
    """Issue an ADO, verify binding, register execution, and confirm replay is blocked."""
    from datetime import datetime, timedelta, timezone

    from shani import (
        ShaniEvaluator,
        StaticAuthorityProvider,
        DecisionType,
        BlastRadius,
        DeniedDecision,
    )
    from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
    from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

    print("\n" + "═" * 60)
    print("  shani check — Quick End-to-End Verification")
    print("═" * 60)

    policy = DecisionPolicyProvider(
        agent_registry={
            "test-agent/v1": AgentIdentity(
                agent_id="test-agent/v1",
                granted_dsal=2,
                allowed_decision_types=frozenset(["remediation"]),
            )
        }
    )
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=policy,
    )
    proposal = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="test-agent/v1",
        description="Restart nginx on prod-web-01",
        target="host:prod-web-01",
        scope=DecisionScope(asset_ids=["host:prod-web-01"]),
        evidence=[EvidenceItem(source="monitor", content="CPU 99% for 5m", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
    )

    result = evaluator.evaluate(proposal)
    if isinstance(result, DeniedDecision):
        print(f"  ✗ Unexpected denial: {result.reason}")
        return 1

    ado = result
    print("  ✓ ADO issued")
    print(f"    decision_id    : {ado.decision_id[:8]}…")
    print(f"    proposal_hash  : {ado.proposal_hash[:16]}…")
    print(f"    authority      : {ado.authority}")
    print(f"    authorized_dsal: {ado.authorized_dsal}")
    print(f"    nonce          : {ado.nonce[:16]}…")
    print(f"    issued_at      : {ado.issued_at.strftime('%H:%M:%S UTC')}")
    print(f"    expires_at     : {ado.expires_at.strftime('%H:%M:%S UTC')}")
    print(f"    signature      : {ado.signature[:16]}…")
    print(f"    exec_context.target: {ado.exec_context.intent_binding.target}")

    assert evaluator.verify_binding(ado, proposal), "verify_binding failed"
    print("  ✓ verify_binding: OK")

    evaluator.register_executed(ado, "test-agent/v1")
    print("  ✓ register_executed: nonce consumed")

    assert not evaluator.verify_binding(ado, proposal), "replay should be blocked"
    print("  ✓ replay blocked:  verify_binding after execution = False")

    print("\n  ✓ End-to-end check passed.\n")
    return 0
