"""
examples/dis_violation/scenario.py

Scenario: DIS integrity violation — replay attack triggers VIOLATED state.

Shows:
  - Normal operation (VALID)
  - Replay attack detection → DIS transitions to VIOLATED
  - All subsequent proposals denied while VIOLATED
  - Manual reset with justification + authority
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
from shani import (
    ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius,
    DeniedDecision, DISStateMachine, DIS,
)
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem
from shani.integrity.monitor import IntegritySignal, IntegritySignalType

def make_proposal(evaluator):
    return DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="soc-agent/v1",
        description="Restart nginx service after memory leak detected by monitoring.",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="Memory 99%", confidence=0.9)],
        confidence=0.9, reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
    )

def run():
    print("=" * 58)
    print("  Scenario: DIS Integrity Violation")
    print("=" * 58)

    dis = DISStateMachine()
    agents = {"soc-agent/v1": AgentIdentity(
        agent_id="soc-agent/v1", granted_dsal=2,
        allowed_decision_types=frozenset(["remediation"]),
    )}
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=2),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
        dis_machine=dis,
    )

    # Step 1: Normal operation
    print(f"\n  [Step 1] Normal operation  DIS={dis.state.value}")
    result = evaluator.evaluate(make_proposal(evaluator))
    if not isinstance(result, DeniedDecision):
        print(f"           ADO issued ✓  dsal={result.authorized_dsal}")
    else:
        print(f"           DENIED: {result.reason}")

    # Step 2: Simulate replay attack signal
    print(f"\n  [Step 2] Replay attack detected → DIS signal")
    evaluator.process_integrity_signal(IntegritySignal(
        signal_type=IntegritySignalType.REPLAY_ATTACK,
        source="nonce-store",
        decision_id="dec-replayed-001",
        detail="Nonce 8f3a... already consumed; second use detected",
    ))
    print(f"           DIS state: {dis.state.value}")

    # Step 3: All proposals now denied
    print(f"\n  [Step 3] All proposals denied while VIOLATED")
    blocked = evaluator.evaluate(make_proposal(evaluator))
    if isinstance(blocked, DeniedDecision):
        print(f"           DENIED ✓  reason: {blocked.reason}")
    else:
        print(f"           ✗ Unexpected authorization")

    # Step 4: Human resets with justification
    print(f"\n  [Step 4] Security team investigates and resets DIS")
    dis.reset_to_valid(
        justification="Replay was traced to a clock-skew bug in agent v1.1. "
                      "Fixed in v1.2. No malicious activity confirmed.",
        authorized_by="alice@example.com",
    )
    print(f"           DIS state: {dis.state.value}")

    # Step 5: Normal operation resumes
    print(f"\n  [Step 5] Normal operation resumes")
    resumed = evaluator.evaluate(make_proposal(evaluator))
    if not isinstance(resumed, DeniedDecision):
        print(f"           ADO issued ✓  dsal={resumed.authorized_dsal}")
    else:
        print(f"           DENIED: {resumed.reason}")

if __name__ == "__main__":
    run()
