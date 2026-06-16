"""
examples/delegation/scenario.py

Scenario: Orchestrator delegates to specialist agents.

Shows:
  - Parent ADO with delegation_rules
  - Child proposal constrained by parent's max_child_dsal
  - Escalation attempt blocked (child cannot exceed parent's grant)
"""

import sys, os

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


def run():
    print("=" * 58)
    print("  Scenario: Delegation — orchestrator → specialist")
    print("=" * 58)

    agents = {
        "orchestrator/v1": AgentIdentity(
            agent_id="orchestrator/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(["remediation", "delegation"]),
        ),
        "specialist/v1": AgentIdentity(
            agent_id="specialist/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(["remediation"]),
        ),
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )

    # Step 1: Orchestrator gets a delegation ADO
    parent_proposal = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="orchestrator/v1",
        description="Coordinate incident response: isolate affected host and rotate credentials. "
        "Delegating isolation to specialist agent.",
        target="host:prod-web-04",
        scope=DecisionScope(asset_ids=["host:prod-web-04"]),
        evidence=[
            EvidenceItem(source="edr", content="Lateral movement detected", confidence=0.91),
            EvidenceItem(source="siem", content="Unusual auth pattern", confidence=0.88),
        ],
        confidence=0.90,
        reversibility=True,
        blast_radius=BlastRadius.SIGNIFICANT,
        delegation=True,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=30),
    )

    parent_ado = evaluator.evaluate(parent_proposal)
    if isinstance(parent_ado, DeniedDecision):
        print(f"  [Shani] Parent DENIED: {parent_ado.reason}")
        return

    print(f"\n  [Step 1] Parent ADO issued")
    print(
        f"           dsal={parent_ado.authorized_dsal}  "
        f"max_child_dsal={parent_ado.delegation_rules.max_child_dsal}  "
        f"max_depth={parent_ado.delegation_rules.max_depth}"
    )

    # Step 2: Specialist uses parent ADO to get its own (lower D-SAL)
    child_proposal = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="specialist/v1",
        description="Isolate host:prod-web-04 from network (block all ingress/egress).",
        target="host:prod-web-04",
        scope=DecisionScope(asset_ids=["host:prod-web-04"]),
        evidence=[
            EvidenceItem(source="edr", content="Process injection confirmed", confidence=0.95),
        ],
        confidence=0.95,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        parent_decision_id=parent_ado.decision_id,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=15),
    )

    child_ado = evaluator.evaluate(child_proposal, parent_ado=parent_ado)
    if isinstance(child_ado, DeniedDecision):
        print(f"  [Step 2] Child DENIED: {child_ado.reason}")
    else:
        print(f"  [Step 2] Child ADO issued  dsal={child_ado.authorized_dsal}  ✓")

    # Step 3: Escalation attempt — child tries for higher D-SAL than parent allows
    # (This is blocked by max_child_dsal invariant at the schema level)
    print(f"\n  [Step 3] Escalation attempt (child tries to exceed parent's grant)...")
    escalation = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="specialist/v1",
        description="Attempting to claim higher authority than delegated.",
        target="host:prod-web-04",
        scope=DecisionScope(asset_ids=["host:prod-web-04"]),
        evidence=[EvidenceItem(source="edr", content="override attempt", confidence=0.5)],
        confidence=0.5,
        reversibility=False,
        blast_radius=BlastRadius.CRITICAL,
        parent_decision_id=parent_ado.decision_id,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
    )
    esc_result = evaluator.evaluate(escalation, parent_ado=parent_ado)
    if isinstance(esc_result, DeniedDecision):
        print(f"  [Step 3] Escalation BLOCKED ✓  reason: {esc_result.reason[:60]}")
    else:
        print(f"  [Step 3] ✗ Escalation succeeded (unexpected)")


if __name__ == "__main__":
    run()
