"""
examples/firewall_chain/scenario.py

Scenario: Firewall rule change chain — shows policy enforcement across risk levels.

Shows:
  - Low-risk proposal (dev, reversible) → auto-approved
  - Medium-risk proposal (prod, reversible) → approved with higher D-SAL
  - High-risk proposal (prod, irreversible, CRITICAL) → blocked by RuleEngine
  - Evidence quality affecting risk score
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


def make_evaluator():
    agents = {
        "network-agent/v1": AgentIdentity(
            agent_id="network-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(["network_action", "remediation"]),
        )
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=4),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )


def make_proposal(target, blast_radius, reversibility, evidence, desc):
    return DecisionProposal(
        decision_type=DecisionType.NETWORK_ACTION,
        proposed_by="network-agent/v1",
        description=desc,
        target=target,
        scope=DecisionScope(asset_ids=[target]),
        evidence=evidence,
        confidence=0.88,
        reversibility=reversibility,
        blast_radius=blast_radius,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
    )


def check(evaluator, proposal, label):
    result = evaluator.evaluate(proposal)
    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        rules = summary.get("rules_triggered", [])
        print(f"  {label}: DENIED  rules={rules}  risk={summary.get('risk_score')}")
    else:
        print(f"  {label}: AUTHORIZED  dsal={result.authorized_dsal}  authority={result.authority}")


def run():
    print("=" * 58)
    print("  Scenario: Firewall Rule Change Chain")
    print("=" * 58)

    ev = make_evaluator()
    good_ev = [
        EvidenceItem(source="siem", content="scan detected", confidence=0.92),
        EvidenceItem(source="edr", content="lateral confirmed", confidence=0.89),
    ]
    weak_ev = [EvidenceItem(source="self-report", content="I think it's needed", confidence=0.4)]

    print()
    check(
        ev,
        make_proposal(
            target="fw:dev-zone",
            blast_radius=BlastRadius.ISOLATED,
            reversibility=True,
            evidence=good_ev,
            desc="Block port 22 on dev firewall zone after scan alert",
        ),
        "Low-risk   (dev, isolated, reversible, good evidence)",
    )

    check(
        ev,
        make_proposal(
            target="fw:prod-ingress",
            blast_radius=BlastRadius.SIGNIFICANT,
            reversibility=True,
            evidence=good_ev,
            desc="Block lateral movement ports on prod ingress firewall",
        ),
        "Med-risk   (prod, significant, reversible, good evidence)",
    )

    check(
        ev,
        make_proposal(
            target="fw:prod-ingress",
            blast_radius=BlastRadius.CRITICAL,
            reversibility=False,
            evidence=good_ev,
            desc="Permanently disable all external ingress on prod firewall",
        ),
        "High-risk  (prod, CRITICAL, irreversible, good evidence)",
    )

    check(
        ev,
        make_proposal(
            target="fw:prod-ingress",
            blast_radius=BlastRadius.SIGNIFICANT,
            reversibility=True,
            evidence=weak_ev,
            desc="Change prod firewall rules based on my assessment",
        ),
        "Weak-evid  (prod, significant, self-reported evidence only)",
    )

    print()


if __name__ == "__main__":
    run()
