"""
examples/github-actions/agent_step.py

Demonstrates how an autonomous CI/CD agent integrates Shani into a
GitHub Actions workflow.

The agent:
  1. Decides to deploy a new release
  2. Emits a DecisionProposal to Shani for authorization
  3. Receives an ADO (authorized) or DeniedDecision (blocked)
  4. Proceeds only if authorized

Run:
    python agent_step.py
"""

from __future__ import annotations

import json
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
        "release-bot/v1": AgentIdentity(
            agent_id="release-bot/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                ["configuration_change", "remediation", "network_action"]
            ),
        )
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )


def make_deploy_proposal() -> DecisionProposal:
    return DecisionProposal(
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        proposed_by="release-bot/v1",
        description="Deploy release v2.4.1 to production cluster prod-us-east-1",
        target="k8s:prod-us-east-1/app/myservice",
        scope=DecisionScope(
            asset_ids=["k8s:prod-us-east-1/app/myservice"],
            resource_types=["k8s:deployment"],
            geographic_boundary="us-east-1",
        ),
        evidence=[
            EvidenceItem(
                source="ci-pipeline",
                content="All 847 tests passed. Security scan: 0 high/critical CVEs.",
                confidence=0.97,
            ),
            EvidenceItem(
                source="staging-canary",
                content="Canary on staging-us-east-1 healthy for 24h. P99 latency -12ms vs baseline.",
                confidence=0.93,
            ),
        ],
        confidence=0.95,
        reversibility=True,
        blast_radius=BlastRadius.SIGNIFICANT,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=60),
    )


def main() -> int:
    print("=" * 60)
    print("  GitHub Actions — Shani Governance Example")
    print("=" * 60)
    print()

    evaluator = build_evaluator()
    proposal = make_deploy_proposal()

    print(f"  Agent: {proposal.proposed_by}")
    print(f"  Action: {proposal.decision_type.value} on {proposal.target}")
    print(
        f"  Risk: blast_radius={proposal.blast_radius.value}, reversible={proposal.reversibility}"
    )
    print(f"  Evidence: {len(proposal.evidence)} sources")
    print()

    print("  Submitting to Shani for authorization…")
    result = evaluator.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        print(f"  ✗ DENIED — {summary['reason']}")
        if summary.get("risk_breakdown"):
            for dim, score in summary["risk_breakdown"].items():
                print(f"    risk.{dim}: {score}")
        print()
        print("  ⚠ Deployment blocked. Manual approval required.")
        print("  → Set GITHUB_ACTIONS=true and configure HITL gate for human escalation.")
        return 1

    ado = result
    print(f"  ✓ AUTHORIZED")
    print(f"    ADO id        : {ado.decision_id[:8]}…")
    print(f"    authority     : {ado.authority}")
    print(f"    authorized_dsal: {ado.authorized_dsal}")
    print(f"    expires_at    : {ado.expires_at.strftime('%H:%M:%S UTC')}")
    print()
    print("  Proceeding with deployment…")
    print("  [deployment simulation — replace with real kubectl/helm/tf apply]")

    evaluator.register_executed(ado, "release-bot/v1")
    print(f"  ✓ ADO nonce consumed — replay prevention active")
    print()
    print("  ✓ Deployment complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
