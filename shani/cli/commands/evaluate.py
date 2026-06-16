"""shani evaluate <proposal.json> — Evaluate a proposal and print the result."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shani.schemas.decision import DecisionProposal


def cmd_evaluate(args: argparse.Namespace) -> int:
    """Load a proposal JSON file, evaluate it, and print the decision."""
    proposal_path = Path(args.proposal)
    if not proposal_path.exists():
        print(f"  error: proposal file not found: {proposal_path}", file=sys.stderr)
        return 1

    try:
        with proposal_path.open() as f:
            raw = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"  error: invalid JSON in {proposal_path}: {exc}", file=sys.stderr)
        return 1

    from datetime import datetime, timedelta, timezone

    from shani import (
        ShaniEvaluator,
        StaticAuthorityProvider,
        DecisionType,
        BlastRadius,
        DeniedDecision,
    )
    from shani.authority.policy import DecisionPolicyProvider
    from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

    # Load optional policy
    policy: DecisionPolicyProvider
    if args.policy:
        from shani.authority.provider import YAMLAuthorityProvider

        authority = YAMLAuthorityProvider(config_path=args.policy)
        policy = DecisionPolicyProvider(allow_unregistered_agents=True)
    else:
        authority = StaticAuthorityProvider(max_dsal=args.max_dsal)
        policy = DecisionPolicyProvider(allow_unregistered_agents=True)

    evaluator = ShaniEvaluator(
        authority_provider=authority,
        decision_policy=policy,
    )

    # Build proposal from JSON
    try:
        proposal = _proposal_from_dict(raw)
    except (KeyError, ValueError) as exc:
        print(f"  error: invalid proposal JSON: {exc}", file=sys.stderr)
        _print_proposal_schema()
        return 1

    result = evaluator.evaluate(proposal)

    if args.output == "json":
        _print_json(result)
    else:
        _print_human(result)

    return 0 if not isinstance(result, DeniedDecision) else 2


def _proposal_from_dict(raw: dict) -> DecisionProposal:
    from datetime import datetime, timedelta, timezone
    from shani import DecisionType, BlastRadius
    from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

    expires_at_raw = raw.get("expires_at")
    if expires_at_raw:
        if isinstance(expires_at_raw, str):
            expires_at = datetime.fromisoformat(expires_at_raw)
        else:
            expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=int(expires_at_raw))
    else:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=10)

    scope_raw = raw.get("scope", {})
    scope = DecisionScope(
        asset_ids=scope_raw.get("asset_ids", []),
        resource_types=scope_raw.get("resource_types", []),
        geographic_boundary=scope_raw.get("geographic_boundary"),
        max_affected_count=scope_raw.get("max_affected_count"),
    )

    evidence = [
        EvidenceItem(
            source=e["source"],
            content=e["content"],
            confidence=float(e.get("confidence", 0.8)),
        )
        for e in raw.get("evidence", [])
    ]

    return DecisionProposal(
        decision_type=DecisionType(raw["decision_type"]),
        proposed_by=raw["proposed_by"],
        description=raw["description"],
        target=raw["target"],
        scope=scope,
        evidence=evidence,
        confidence=float(raw.get("confidence", 0.8)),
        reversibility=bool(raw.get("reversibility", True)),
        blast_radius=BlastRadius(raw.get("blast_radius", "limited")),
        expires_at=expires_at,
    )


def _print_human(result: object) -> None:
    from shani import DeniedDecision
    from shani.schemas.decision import AuthorizedDecisionObject
    from shani.schemas.posture import PostureRefinementRequest

    print()
    if isinstance(result, DeniedDecision):
        print("  ✗ DENIED")
        summary = result.to_human_summary()
        print(f"    reason         : {summary['reason']}")
        if summary.get("risk_score"):
            print(f"    risk_score     : {summary['risk_score']}")
        if summary.get("rules_triggered"):
            print(f"    rules_triggered: {summary['rules_triggered']}")
        if summary.get("risk_breakdown"):
            for dim, score in summary["risk_breakdown"].items():
                print(f"    risk.{dim:<18}: {score}")
    elif isinstance(result, PostureRefinementRequest):
        print("  ⚠ POSTURE REFINEMENT REQUIRED")
        print(f"    proposal_id    : {result.proposal_id[:8]}…")
        print(f"    principal_id   : {result.principal_id}")
        print(f"    ambiguity      : {result.ambiguity}")
        if result.unresolved:
            print(f"    unresolved     : {result.unresolved}")
    else:
        ado = result
        print("  ✓ AUTHORIZED")
        print(f"    decision_id    : {ado.decision_id[:8]}…")
        print(f"    authorized_dsal: {ado.authorized_dsal}")
        print(f"    authority      : {ado.authority}")
        print(f"    expires_at     : {ado.expires_at.strftime('%H:%M:%S UTC')}")
        print(f"    signature      : {ado.signature[:16]}…")
        print(f"    target         : {ado.exec_context.intent_binding.target}")
    print()


def _print_json(result: object) -> None:
    import json as _json
    from shani import DeniedDecision
    from shani.schemas.posture import PostureRefinementRequest

    if isinstance(result, DeniedDecision):
        out = {
            "status": "denied",
            **result.to_human_summary(),
        }
    elif isinstance(result, PostureRefinementRequest):
        out = {
            "status": "refinement_required",
            "proposal_id": result.proposal_id,
            "principal_id": result.principal_id,
            "ambiguity": result.ambiguity,
            "unresolved": result.unresolved,
        }
    else:
        ado = result
        out = {
            "status": "authorized",
            "decision_id": ado.decision_id,
            "authorized_dsal": ado.authorized_dsal,
            "authority": ado.authority,
            "issued_at": ado.issued_at.isoformat(),
            "expires_at": ado.expires_at.isoformat(),
            "proposal_hash": ado.proposal_hash,
            "signature": ado.signature,
        }

    print(_json.dumps(out, indent=2))


def _print_proposal_schema() -> None:
    print("""
  Expected proposal.json format:
  {
    "decision_type": "remediation",
    "proposed_by": "my-agent/v1",
    "description": "Restart nginx on prod-web-01",
    "target": "host:prod-web-01",
    "scope": { "asset_ids": ["host:prod-web-01"] },
    "evidence": [
      { "source": "monitor", "content": "CPU 99%", "confidence": 0.9 }
    ],
    "confidence": 0.9,
    "reversibility": true,
    "blast_radius": "limited",
    "expires_at": "2026-01-01T12:05:00+00:00"
  }

  Valid decision_type values: remediation, configuration_change,
    network_action, data_access, delegation, policy_update,
    browser_action, agent_task, tool_call

  Valid blast_radius values: isolated, limited, significant, critical
""")
