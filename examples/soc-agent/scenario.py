"""
examples/soc-agent/scenario.py

SOC automated remediation governed by Shani.

Simulates a Security Operations Center agent that:
  1. Receives security signals (SIEM, EDR, threat intel)
  2. Proposes remediation actions to Shani
  3. Executes authorized actions, escalates denied ones

Run:
    python scenario.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa: F401
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
from dataclasses import dataclass

from shani import (
    ShaniEvaluator,
    StaticAuthorityProvider,
    DecisionType,
    BlastRadius,
    DeniedDecision,
    DISIntegrityMonitor,
)
from shani.schemas.state import DISStateMachine
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem


@dataclass
class SecurityAlert:
    """Simulates an incoming security alert from SIEM/EDR."""

    alert_id: str
    severity: str  # critical, high, medium, low
    target: str  # affected resource
    description: str
    sources: list[tuple[str, str, float]]  # [(source, content, confidence)]


def build_evaluator() -> ShaniEvaluator:
    agents = {
        "soc-agent/v1": AgentIdentity(
            agent_id="soc-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                [
                    "remediation",
                    "network_action",
                    "configuration_change",
                ]
            ),
        ),
    }
    dis = DISStateMachine()
    monitor = DISIntegrityMonitor(dis)
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
        dis_machine=dis,
        integrity_monitor=monitor,
    )


def alert_to_proposal(alert: SecurityAlert) -> DecisionProposal:
    """Convert a security alert to a Shani DecisionProposal."""
    severity_to_blast = {
        "low": BlastRadius.ISOLATED,
        "medium": BlastRadius.LIMITED,
        "high": BlastRadius.SIGNIFICANT,
        "critical": BlastRadius.CRITICAL,
    }
    blast = severity_to_blast.get(alert.severity, BlastRadius.LIMITED)
    is_prod = "prod" in alert.target.lower()

    return DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="soc-agent/v1",
        description=f"Automated remediation for {alert.alert_id}: {alert.description}",
        target=alert.target,
        scope=DecisionScope(
            asset_ids=[alert.target],
            geographic_boundary="us-east-1",
        ),
        evidence=[
            EvidenceItem(source=src, content=content, confidence=conf)
            for src, content, conf in alert.sources
        ],
        confidence=min(c for _, _, c in alert.sources),
        reversibility=True,
        blast_radius=blast,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
    )


def handle_alert(evaluator: ShaniEvaluator, alert: SecurityAlert) -> None:
    print(f"\n  Alert {alert.alert_id} [{alert.severity.upper()}]")
    print(f"  Target   : {alert.target}")
    print(f"  Signal   : {alert.description}")

    proposal = alert_to_proposal(alert)
    result = evaluator.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        print(f"  ✗ BLOCKED  — {summary['reason'][:70]}")
        if summary.get("risk_score"):
            print(
                f"    risk_score={summary['risk_score']}  dsal={summary.get('effective_dsal', '?')}"
            )
        print(f"  → Escalating to SOC analyst for manual review…")
    else:
        ado = result
        print(f"  ✓ AUTHORIZED  dsal={ado.authorized_dsal}  authority={ado.authority}")
        print(f"    ADO {ado.decision_id[:8]}… expires {ado.expires_at.strftime('%H:%M:%S UTC')}")
        print(f"  → Executing remediation: {alert.description}")
        evaluator.register_executed(ado, "soc-agent/v1")
        print(f"    ✓ Executed. Nonce consumed — replay prevention active.")


SCENARIOS: list[SecurityAlert] = [
    SecurityAlert(
        alert_id="INC-001",
        severity="low",
        target="host:dev-sandbox-03",
        description="Isolate dev sandbox exhibiting C2 beacon behaviour",
        sources=[
            ("edr", "Unusual outbound DNS to known C2 domain beacon.evil.io", 0.88),
        ],
    ),
    SecurityAlert(
        alert_id="INC-002",
        severity="high",
        target="host:prod-web-07",
        description="Block lateral movement from compromised prod web host",
        sources=[
            ("siem", "Credential stuffing from prod-web-07 internal IP", 0.91),
            ("edr", "Mimikatz-like memory access pattern detected on prod-web-07", 0.85),
            ("ndr", "Anomalous SMB traffic to 14 internal hosts in 3 min", 0.80),
        ],
    ),
    SecurityAlert(
        alert_id="INC-003",
        severity="critical",
        target="k8s:prod/Namespace/*",
        description="Wipe entire prod namespace (ransomware simulation exercise)",
        sources=[
            ("red-team", "Simulated ransomware encryption of all prod PVCs", 0.99),
        ],
    ),
    SecurityAlert(
        alert_id="INC-004",
        severity="medium",
        target="host:staging-db-02",
        description="Rotate compromised DB credentials on staging",
        sources=[
            ("secret-scanner", "Plaintext DB password found in git commit abc1234", 0.95),
            ("audit-log", "Credential accessed by unknown IP 203.0.113.50", 0.87),
        ],
    ),
]


def main() -> None:
    print("=" * 60)
    print("  SOC Automated Remediation — Shani Governance Example")
    print("=" * 60)
    print(f"\n  Processing {len(SCENARIOS)} security alerts…")

    evaluator = build_evaluator()
    for alert in SCENARIOS:
        handle_alert(evaluator, alert)

    print()


if __name__ == "__main__":
    main()
