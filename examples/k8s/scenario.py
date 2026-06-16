"""
examples/k8s/scenario.py

Demonstrates Shani as a Kubernetes admission controller.

Simulates the admission webhook flow without a real K8s cluster:
  - A GitOps agent proposes a deployment rollout (authorized)
  - A security scanner agent proposes deleting a running pod (denied)
  - A human-triggered rollback (high blast radius, authorized via D-SAL 3)

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

from shani import (
    ShaniEvaluator,
    StaticAuthorityProvider,
    DecisionType,
    BlastRadius,
    DeniedDecision,
)
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem


def build_evaluator() -> ShaniEvaluator:
    agents = {
        "gitops-agent/v1": AgentIdentity(
            agent_id="gitops-agent/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(["configuration_change", "data_access"]),
        ),
        "security-scanner/v1": AgentIdentity(
            agent_id="security-scanner/v1",
            granted_dsal=1,
            allowed_decision_types=frozenset(["remediation"]),
        ),
        "sre-automation/v1": AgentIdentity(
            agent_id="sre-automation/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                [
                    "configuration_change",
                    "remediation",
                    "network_action",
                ]
            ),
        ),
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )


def show(label: str, result: object) -> None:
    print(f"\n  {label}")
    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        print(f"    ✗ DENIED  → {summary['reason'][:70]}")
        if summary.get("risk_score"):
            print(
                f"      risk_score={summary['risk_score']}  dsal={summary.get('effective_dsal', '?')}"
            )
    else:
        ado = result
        print(f"    ✓ AUTHORIZED  dsal={ado.authorized_dsal}  authority={ado.authority}")
        print(f"      ADO {ado.decision_id[:8]}… expires {ado.expires_at.strftime('%H:%M:%S UTC')}")


def main() -> None:
    print("=" * 60)
    print("  K8s Admission Control — Shani Governance Example")
    print("=" * 60)

    evaluator = build_evaluator()
    now = datetime.now(tz=timezone.utc)

    # Case 1: GitOps rolling update — authorized
    show(
        "Case 1: GitOps rolling update (config change, limited blast)",
        evaluator.evaluate(
            DecisionProposal(
                decision_type=DecisionType.CONFIGURATION_CHANGE,
                proposed_by="gitops-agent/v1",
                description="Roll out v1.8.3 → v1.9.0 on Deployment/api-server (3 replicas)",
                target="k8s:prod/Deployment/api-server",
                scope=DecisionScope(
                    asset_ids=["k8s:prod/Deployment/api-server"], max_affected_count=3
                ),
                evidence=[
                    EvidenceItem(
                        source="ci-checks",
                        content="Tests green. CVE scan: 0 critical. Staging healthy 48h.",
                        confidence=0.96,
                    ),
                ],
                confidence=0.94,
                reversibility=True,
                blast_radius=BlastRadius.LIMITED,
                expires_at=now + timedelta(minutes=15),
            )
        ),
    )

    # Case 2: Security scanner tries to delete a running pod — denied (D-SAL too high)
    show(
        "Case 2: Scanner deletes running pod (significant, irreversible)",
        evaluator.evaluate(
            DecisionProposal(
                decision_type=DecisionType.REMEDIATION,
                proposed_by="security-scanner/v1",
                description="Delete pod/api-server-7f8d9b5-xk2q9 (CVE-2025-9999 detected in process)",
                target="k8s:prod/Pod/api-server-7f8d9b5-xk2q9",
                scope=DecisionScope(asset_ids=["k8s:prod/Pod/api-server-7f8d9b5-xk2q9"]),
                evidence=[
                    EvidenceItem(
                        source="vuln-scanner",
                        content="CVE-2025-9999 exploited in process PID 1234.",
                        confidence=0.72,
                    ),
                ],
                confidence=0.72,
                reversibility=False,
                blast_radius=BlastRadius.SIGNIFICANT,
                expires_at=now + timedelta(minutes=5),
            )
        ),
    )

    # Case 3: SRE automation cluster-wide rollback — authorized (D-SAL 3)
    show(
        "Case 3: SRE automated rollback (critical, reversible, D-SAL 3)",
        evaluator.evaluate(
            DecisionProposal(
                decision_type=DecisionType.CONFIGURATION_CHANGE,
                proposed_by="sre-automation/v1",
                description="Emergency rollback of all prod Deployments to last known good version",
                target="k8s:prod/*",
                scope=DecisionScope(
                    resource_types=["k8s:deployment"],
                    geographic_boundary="us-east-1",
                ),
                evidence=[
                    EvidenceItem(
                        source="alertmanager",
                        content="Error rate >40% across all prod services for 8m. SLO breach.",
                        confidence=0.99,
                    ),
                    EvidenceItem(
                        source="apm",
                        content="Span error spike correlated with v1.9.0 rollout at 12:03 UTC.",
                        confidence=0.95,
                    ),
                ],
                confidence=0.96,
                reversibility=True,
                blast_radius=BlastRadius.CRITICAL,
                expires_at=now + timedelta(minutes=10),
            )
        ),
    )

    print()


if __name__ == "__main__":
    main()
