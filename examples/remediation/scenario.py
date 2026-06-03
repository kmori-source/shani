"""
examples/remediation/scenario.py

Scenario: Reversible remediation — remove an overpermissive firewall rule.

Shows:
  - Basic proposal → ADO → execution flow
  - Evidence from system sensor (SIEM)
  - D-SAL computed from context, not declared by agent
  - DenialContext when denied
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _s = _iu.spec_from_file_location("_compat", str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"))
    _m = _iu.module_from_spec(_s); _s.loader.exec_module(_m)
    _sh = _t.ModuleType("pydantic")
    for _k in ("BaseModel","Field","field_validator","model_validator"): setattr(_sh, _k, getattr(_m, _k))
    sys.modules["pydantic"] = _sh
import warnings; warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone
from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius, DeniedDecision
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

def run():
    print("=" * 58)
    print("  Scenario: Remediation — remove overpermissive firewall rule")
    print("=" * 58)

    agents = {"soc-agent/v1": AgentIdentity(
        agent_id="soc-agent/v1", granted_dsal=2,
        allowed_decision_types=frozenset(["remediation"]),
    )}
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=2),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )

    proposal = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="soc-agent/v1",
        description="Remove overpermissive inbound rule sg-0abc123 (port 0-65535 from 0.0.0.0/0). "
                    "Rule was added erroneously during maintenance window. No active sessions affected.",
        target="aws:sg-0abc123",
        scope=DecisionScope(asset_ids=["aws:sg-0abc123"]),
        evidence=[
            EvidenceItem(source="siem-alert", content="Port scan detected on sg-0abc123", confidence=0.93),
            EvidenceItem(source="cloudwatch", content="0 active connections on exposed ports", confidence=0.99),
        ],
        confidence=0.92,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=15),
    )

    print(f"\n  [Agent] proposal={proposal.decision_id[:8]}  type={proposal.decision_type.value}")
    print(f"          target={proposal.target}  reversible={proposal.reversibility}")
    print(f"          evidence: {len(proposal.evidence)} items")

    result = evaluator.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        print(f"\n  [Shani] DENIED ✗")
        print(f"          reason: {summary['reason']}")
        print(f"          risk_score: {summary.get('risk_score')}")
    else:
        print(f"\n  [Shani] AUTHORIZED ✓")
        print(f"          authority:      {result.authority}")
        print(f"          authorized_dsal: {result.authorized_dsal}")
        print(f"          proposal_hash:  {result.proposal_hash[:16]}...")
        print(f"          signature:      {result.signature[:16]}...")

        verified = evaluator.verify_binding(result, proposal)
        print(f"          verify_binding: {verified}")

        evaluator.register_executed(result, agent_id="soc-agent/v1")
        replay = evaluator.verify_binding(result, proposal)
        print(f"          replay attempt: {replay} (expected False)")
        print(f"\n  ✓ Firewall rule removal authorized and executed")

if __name__ == "__main__":
    run()
