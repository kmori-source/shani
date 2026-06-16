"""
examples/cross-org/scenario.py

Cross-organizational supply chain governance with propagated_constraints (SPEC §8.8).

Scenario:
  - Org A (upstream supplier) releases a new library version via an agent
  - Org A's Shani evaluator issues a cross-org ADO with propagated_constraints
    from Org A's UserPosture
  - Org B (downstream consumer) receives the cross-org ADO and validates
    its own update proposal against the propagated constraints

Demonstrates:
  1. Cross-org ADO issuance with propagated_constraints embedded
  2. Org B validating an update proposal against propagated constraints
  3. Ambiguous case: cross-org ADO with empty propagated_constraints
  4. Incompatible constraints: Org A allows irreversible, Org B's posture rejects

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
    UserPosture,
    PostureConstraints,
)
from shani.schemas.posture import PostureRefinementRequest
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import (
    DecisionProposal,
    DecisionScope,
    EvidenceItem,
    AuthorizedDecisionObject,
)


def build_org_a_evaluator() -> ShaniEvaluator:
    """Org A: upstream library supplier."""
    posture = UserPosture(
        version="1.0",
        principal_id="org-a",
        signed_at=datetime.now(tz=timezone.utc),
        intent_statement="Supply chain agent: only publish library updates, no prod ops",
        simulation_ref="sim-org-a-2026-01",
        constraints=PostureConstraints(
            target_scope=r"pkg:.*",  # only package registries
            max_blast_radius="significant",
            reversibility_required=False,  # package publishes are irreversible by design
            minimum_evidence=1,
        ),
    )
    agents = {
        "release-agent-a/v1": AgentIdentity(
            agent_id="release-agent-a/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(["configuration_change", "data_access"]),
        ),
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
        user_posture=posture,
        org_id="org-a",
    )


def build_org_b_evaluator(posture: UserPosture) -> ShaniEvaluator:
    """Org B: downstream consumer with stricter posture."""
    agents = {
        "update-agent-b/v1": AgentIdentity(
            agent_id="update-agent-b/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(["configuration_change"]),
        ),
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
        user_posture=posture,
        org_id="org-b",
    )


def show(label: str, result: object) -> None:
    print(f"\n  {label}")
    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        print(f"    ✗ DENIED  → {summary['reason'][:72]}")
    elif isinstance(result, PostureRefinementRequest):
        print(f"    ⚠ REFINEMENT REQUIRED")
        print(f"      principal_id : {result.principal_id}")
        print(f"      ambiguity    : {result.ambiguity[:72]}")
        if result.unresolved:
            print(f"      unresolved   : {result.unresolved}")
    else:
        ado = result
        print(f"    ✓ AUTHORIZED  dsal={ado.authorized_dsal}  authority={ado.authority}")
        if ado.propagated_constraints:
            print(f"      propagated_constraints ({len(ado.propagated_constraints)}):")
            for c in ado.propagated_constraints:
                print(f"        • {c}")
        if ado.origin_org:
            print(f"      origin_org   : {ado.origin_org}")


def main() -> None:
    print("=" * 60)
    print("  Cross-Org Supply Chain — Shani Governance Example")
    print("=" * 60)

    now = datetime.now(tz=timezone.utc)

    # ── Org A: issue cross-org ADO for library publish ─────────────────────
    print("\n  [Org A — upstream supplier]")
    org_a = build_org_a_evaluator()

    # Step 1: Org A agent proposes publishing a new library version
    proposal_a = DecisionProposal(
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        proposed_by="release-agent-a/v1",
        description="Publish mylib v3.2.1 to PyPI — cross-org supply chain action",
        target="pkg:pypi/mylib@3.2.1",
        scope=DecisionScope(asset_ids=["pkg:pypi/mylib@3.2.1"]),
        evidence=[
            EvidenceItem(
                source="ci",
                content="Tests green. SBOM verified. No new CVEs vs v3.2.0.",
                confidence=0.96,
            ),
        ],
        confidence=0.96,
        reversibility=False,  # package publish is permanent
        blast_radius=BlastRadius.SIGNIFICANT,
        expires_at=now + timedelta(minutes=30),
        origin_org="org-a",  # marks this as a cross-org action
    )

    ado_a = org_a.evaluate(proposal_a)
    show("Step 1: Org A agent publishes library v3.2.1", ado_a)

    # ── Org B: receive cross-org ADO and validate downstream update ─────────
    print("\n  [Org B — downstream consumer]")

    # Org B has stricter posture: only reversible ops, no prod targets
    org_b_posture = UserPosture(
        version="2.0",
        principal_id="org-b",
        signed_at=datetime.now(tz=timezone.utc),
        intent_statement="Downstream consumer: only update dev dependencies, reversible only",
        simulation_ref="sim-org-b-2026-01",
        constraints=PostureConstraints(
            target_scope=r".*dev.*|.*staging.*",
            max_blast_radius="limited",
            reversibility_required=True,
            minimum_evidence=1,
        ),
    )
    org_b = build_org_b_evaluator(org_b_posture)

    # Step 2: Org B agent proposes to update mylib in dev environment
    # (passes Org B's posture AND Org A's propagated constraints)
    proposal_b_dev = DecisionProposal(
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        proposed_by="update-agent-b/v1",
        description="Update mylib 3.2.0→3.2.1 in dev environment",
        target="k8s:dev/Deployment/api-server",
        scope=DecisionScope(asset_ids=["k8s:dev/Deployment/api-server"]),
        evidence=[
            EvidenceItem(
                source="depbot",
                content="mylib 3.2.1 available. Compatibility matrix: OK.",
                confidence=0.90,
            ),
        ],
        confidence=0.90,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=now + timedelta(minutes=15),
    )

    parent_ado = ado_a if not isinstance(ado_a, DeniedDecision) else None
    result_b_dev = org_b.evaluate(proposal_b_dev, parent_ado=parent_ado)
    show("Step 2: Org B updates mylib in dev (within constraints)", result_b_dev)

    # Step 3: Org B agent proposes update in PROD — violates Org B's posture
    # (target_scope only allows dev/staging)
    proposal_b_prod = DecisionProposal(
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        proposed_by="update-agent-b/v1",
        description="Update mylib 3.2.0→3.2.1 in PRODUCTION",
        target="k8s:prod/Deployment/api-server",
        scope=DecisionScope(asset_ids=["k8s:prod/Deployment/api-server"]),
        evidence=[
            EvidenceItem(
                source="depbot",
                content="mylib 3.2.1 available. Compatibility matrix: OK.",
                confidence=0.90,
            ),
        ],
        confidence=0.90,
        reversibility=True,
        blast_radius=BlastRadius.SIGNIFICANT,
        expires_at=now + timedelta(minutes=15),
    )

    result_b_prod = org_b.evaluate(proposal_b_prod, parent_ado=parent_ado)
    show("Step 3: Org B updates mylib in PROD (violates org_b posture)", result_b_prod)

    # Step 4: Cross-org ADO with EMPTY propagated_constraints → AMBIGUOUS
    # This tests SPEC §8.9: empty propagated_constraints MUST be AMBIGUOUS
    print("\n  [SPEC §8.9 compliance check]")

    # Simulate receiving a cross-org ADO with no propagated_constraints
    empty_cross_org = DecisionProposal(
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        proposed_by="update-agent-b/v1",
        description="Update mylib from external vendor (no propagated constraints)",
        target="k8s:dev/Deployment/api-server",
        scope=DecisionScope(asset_ids=["k8s:dev/Deployment/api-server"]),
        evidence=[
            EvidenceItem(source="vendor", content="Vendor says update is safe", confidence=0.70),
        ],
        confidence=0.70,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=now + timedelta(minutes=15),
    )

    # Build a fake parent ADO with origin_org but empty propagated_constraints
    from shani.schemas.decision import (
        AuthorizedDecisionObject,
        ExecContext,
        IntentBinding,
        DelegationRules,
    )
    import uuid, hashlib, base64

    fake_parent = AuthorizedDecisionObject(
        decision_id=str(uuid.uuid4()),
        authorized_dsal=2,
        authority="org-unknown",
        expires_at=now + timedelta(minutes=60),
        proposal_hash=hashlib.sha256(b"fake").hexdigest(),
        delegation_rules=DelegationRules(
            allowed_sub_decisions=["configuration_change"],
            max_child_dsal=1,
            max_depth=2,
            max_children=5,
        ),
        signature=base64.b64encode(b"fake").decode(),
        propagated_constraints=[],  # intentionally empty
        origin_org="unknown-vendor",
        exec_context=ExecContext(
            decision_type=DecisionType.CONFIGURATION_CHANGE,
            intent_binding=IntentBinding(
                intent="update:mylib",
                target="pkg:pypi/mylib@3.2.1",
                scope_summary="package",
                expected_effect="library update",
                reversibility=False,
            ),
        ),
    )

    result_ambiguous = org_b.evaluate(empty_cross_org, parent_ado=fake_parent)
    show("Step 4: Cross-org ADO with empty propagated_constraints (SPEC §8.9)", result_ambiguous)

    print()


if __name__ == "__main__":
    main()
