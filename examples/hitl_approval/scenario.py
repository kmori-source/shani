"""
examples/hitl_approval/scenario.py

Scenario: Human-in-the-Loop approval for high-risk operations.

Shows:
  - D-SAL 1 (low risk) → auto-approved, no human needed
  - D-SAL 2 (medium risk, prod target) → HITL required
  - Human approves or denies via CallbackApprovalChannel
  - DenialContext shown when denied

Run modes:
  python scenario.py           # auto-approve all
  SHANI_HITL_AUTO=deny python scenario.py   # auto-deny all
"""

import sys, os, threading, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl

    _s = _iu.spec_from_file_location(
        "_compat", str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py")
    )
    _m = _iu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    _sh = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_sh, _k, getattr(_m, _k))
    sys.modules["pydantic"] = _sh
import warnings

warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone
from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius, DeniedDecision
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel

HITL_AUTO = os.environ.get("SHANI_HITL_AUTO", "approve").lower()


def build_gate(channel: CallbackApprovalChannel) -> HITLGate:
    agents = {
        "ops-agent/v1": AgentIdentity(
            agent_id="ops-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                ["remediation", "configuration_change", "network_action"]
            ),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    return HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=2,
        timeout_minutes=2,
    )


def start_auto_responder(channel: CallbackApprovalChannel):
    """Auto-approve or auto-deny pending requests (simulates a human)."""

    def loop():
        seen = set()
        for _ in range(120):
            time.sleep(0.3)
            for req in channel.get_pending():
                if req.request_id in seen:
                    continue
                seen.add(req.request_id)
                print(f"\n  ┌─ HITL ─────────────────────────────────────")
                print(f"  │  type={req.decision_type}  target={req.target}")
                print(f"  │  authority={req.required_authority}")
                print(f"  └─────────────────────────────────────────────")
                time.sleep(0.2)
                if HITL_AUTO == "deny":
                    channel.deny(req.request_id, "operator@example.com", "auto-deny for demo")
                    print("  → ✗ Denied")
                else:
                    channel.approve(req.request_id, "operator@example.com", "auto-approve for demo")
                    print("  → ✓ Approved")

    threading.Thread(target=loop, daemon=True).start()


def make_proposal(target, blast_radius, evidence, description, reversibility=True):
    return DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="ops-agent/v1",
        description=description,
        target=target,
        scope=DecisionScope(asset_ids=[target]),
        evidence=evidence,
        confidence=0.88,
        reversibility=reversibility,
        blast_radius=blast_radius,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
    )


def show_result(label, result):
    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        print(f"  {label}: DENIED")
        print(f"           reason: {summary['reason'][:70]}")
        if summary.get("risk_score"):
            print(f"           risk_score: {summary['risk_score']}")
        if summary.get("rules_triggered"):
            print(f"           rules: {summary['rules_triggered']}")
    else:
        print(f"  {label}: AUTHORIZED  dsal={result.authorized_dsal}  authority={result.authority}")


def run():
    print("=" * 58)
    print(f"  Scenario: HITL Approval  (SHANI_HITL_AUTO={HITL_AUTO})")
    print("=" * 58)

    channel = CallbackApprovalChannel()
    gate = build_gate(channel)
    start_auto_responder(channel)

    print()

    # Case 1: Low risk (dev, isolated) → D-SAL 1 → auto-approved, no HITL
    result = gate.evaluate(
        make_proposal(
            target="host:dev-01",
            blast_radius=BlastRadius.ISOLATED,
            evidence=[EvidenceItem(source="monitor", content="CPU 99%", confidence=0.9)],
            description="Restart nginx on dev host after memory leak detected by monitoring",
        )
    )
    show_result("D-SAL 1 (dev, isolated)    ", result)

    # Case 2: Medium risk (prod target) → D-SAL 2 → HITL required
    result = gate.evaluate(
        make_proposal(
            target="host:prod-web-01",
            blast_radius=BlastRadius.LIMITED,
            evidence=[
                EvidenceItem(
                    source="siem", content="Anomalous traffic on prod-web-01", confidence=0.91
                ),
                EvidenceItem(source="edr", content="Suspicious process spawn", confidence=0.87),
            ],
            description="Isolate prod-web-01 from network segment after SIEM alert. "
            "Two independent sensors confirm anomalous behavior.",
        )
    )
    show_result("D-SAL 2 (prod, HITL)      ", result)

    # Case 3: CRITICAL + irreversible → RuleEngine hard DENY
    result = gate.evaluate(
        make_proposal(
            target="host:prod-db-cluster",
            blast_radius=BlastRadius.CRITICAL,
            evidence=[EvidenceItem(source="monitor", content="high load", confidence=0.7)],
            description="Emergency permanent shutdown of prod database cluster — cannot be undone",
            reversibility=False,
        )
    )
    show_result("CRITICAL+irreversible (deny)", result)

    print()


if __name__ == "__main__":
    run()
