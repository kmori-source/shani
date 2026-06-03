"""
tests/propagation/fixtures.py

Shared factories for the propagation test suite.

All factories are deterministic and accept keyword overrides so individual
tests can vary specific fields without duplicating boilerplate.
"""
from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from shani import (
    BlastRadius,
    DecisionType,
    DeniedDecision,
    PostureConstraints,
    ShaniEvaluator,
    StaticAuthorityProvider,
    UserPosture,
)
from shani.authority.policy import (
    AgentIdentity,
    DecisionPolicyProvider,
    OrgPolicy,
    OrgPolicyAbsoluteConstraints,
)
from shani.schemas.decision import (
    AuthorizedDecisionObject,
    DecisionProposal,
    DecisionScope,
    DelegationRules,
    EvidenceItem,
    ExecContext,
    IntentBinding,
)
from shani.security.replay_store import InMemoryNonceStore


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def future(seconds: int = 300) -> datetime:
    return utcnow() + timedelta(seconds=seconds)


def past(seconds: int = 10) -> datetime:
    return utcnow() - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Agent registries
# ---------------------------------------------------------------------------

PROPAGATION_AGENTS: dict[str, AgentIdentity] = {
    "agent/alpha": AgentIdentity(
        agent_id="agent/alpha",
        granted_dsal=3,
        allowed_decision_types=frozenset(["remediation", "configuration_change", "data_access"]),
    ),
    "agent/beta": AgentIdentity(
        agent_id="agent/beta",
        granted_dsal=3,
        allowed_decision_types=frozenset(["remediation", "configuration_change", "data_access"]),
    ),
    "agent/gamma": AgentIdentity(
        agent_id="agent/gamma",
        granted_dsal=2,
        allowed_decision_types=frozenset(["remediation", "configuration_change"]),
    ),
    "agent/delta": AgentIdentity(
        agent_id="agent/delta",
        granted_dsal=2,
        allowed_decision_types=frozenset(["remediation"]),
    ),
}


# ---------------------------------------------------------------------------
# Evaluator factory
# ---------------------------------------------------------------------------


def make_evaluator(
    *,
    max_dsal: int = 3,
    user_posture: UserPosture | None = None,
    org_id: str | None = None,
    org_policy: OrgPolicy | None = None,
    nonce_store: InMemoryNonceStore | None = None,
    agents: dict[str, AgentIdentity] | None = None,
) -> ShaniEvaluator:
    policy = DecisionPolicyProvider(
        agent_registry=agents if agents is not None else PROPAGATION_AGENTS,
        org_policy=org_policy,
    )
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=max_dsal),
        decision_policy=policy,
        user_posture=user_posture,
        nonce_store=nonce_store if nonce_store is not None else InMemoryNonceStore(),
        org_id=org_id,
    )


def make_cross_org_evaluator(
    *,
    org_id: str = "org-alpha",
    posture: UserPosture | None = None,  # None disables PostureEngine for most tests
    cross_org_min_dsal: int = 1,
) -> ShaniEvaluator:
    """Create an evaluator configured for cross-org operation."""
    org_policy = OrgPolicy(
        absolute_constraints=OrgPolicyAbsoluteConstraints(
            max_blast_radius="critical",
            cross_org_min_dsal=cross_org_min_dsal,
        )
    )
    return make_evaluator(
        user_posture=posture,
        org_id=org_id,
        org_policy=org_policy,
    )
    return make_evaluator(
        user_posture=posture,
        org_id=org_id,
        org_policy=org_policy,
    )


# ---------------------------------------------------------------------------
# Posture factory
# ---------------------------------------------------------------------------


def make_posture(
    *,
    principal_id: str = "test-principal@example.com",
    target_scope: str = "host:dev-.*",
    max_blast_radius: str = "limited",
    reversibility_required: bool = True,
    minimum_evidence: int = 1,
    posture_signature: str | None = None,  # None skips signature verification in PostureEngine
) -> UserPosture:
    return UserPosture(
        version="1.0",
        principal_id=principal_id,
        signed_at=utcnow(),
        intent_statement="Propagation test posture.",
        simulation_ref="sim-propagation-001",
        constraints=PostureConstraints(
            target_scope=target_scope,
            max_blast_radius=max_blast_radius,
            reversibility_required=reversibility_required,
            minimum_evidence=minimum_evidence,
        ),
        posture_signature=posture_signature,
    )


# ---------------------------------------------------------------------------
# Proposal factory
# ---------------------------------------------------------------------------


def make_proposal(**kwargs) -> DecisionProposal:
    defaults: dict = dict(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="agent/alpha",
        description="Test action for propagation suite",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="test evidence", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=future(300),
    )
    defaults.update(kwargs)
    return DecisionProposal(**defaults)


# ---------------------------------------------------------------------------
# ADO helpers
# ---------------------------------------------------------------------------


def make_valid_ado(
    evaluator: ShaniEvaluator,
    proposal: DecisionProposal,
) -> AuthorizedDecisionObject:
    """Evaluate and return ADO; raise if denied."""
    from shani.schemas.posture import PostureRefinementRequest
    result = evaluator.evaluate(proposal)
    if isinstance(result, DeniedDecision):
        raise RuntimeError(f"Unexpected denial in fixture: {result.reason}")
    if isinstance(result, PostureRefinementRequest):
        raise RuntimeError(
            f"PostureRefinementRequest returned for proposal {result.proposal_id}: "
            f"ambiguity={result.ambiguity!r}. "
            f"Fix: expand posture constraints (target_scope, max_blast_radius, etc.) "
            f"or set posture=None to skip posture check in this test."
        )
    if not isinstance(result, AuthorizedDecisionObject):
        raise RuntimeError(f"Unexpected result type: {type(result)}")
    return result


def make_cross_org_ado(
    evaluator: ShaniEvaluator,
    *,
    origin_org: str = "org-alpha",
    propagated_constraints: list[str] | None = None,
    max_child_dsal: int = 2,
) -> AuthorizedDecisionObject:
    """Issue a cross-org ADO with propagated_constraints embedded."""
    proposal = make_proposal(
        proposed_by="agent/alpha",
        decision_type=DecisionType.REMEDIATION,
        origin_org=origin_org,
    )
    ado = make_valid_ado(evaluator, proposal)
    if propagated_constraints is None:
        propagated_constraints = [
            "target_scope:host:dev-.*",
            "max_blast_radius:limited",
            "reversibility_required:true",
            "minimum_evidence:1",
        ]
    deleg = DelegationRules(
        allowed_sub_decisions=["remediation", "configuration_change"],
        max_child_dsal=max_child_dsal,
        max_depth=3,
        max_children=10,
    )
    return ado.model_copy(update={
        "origin_org": origin_org,
        "propagated_constraints": propagated_constraints,
        "delegation_rules": deleg,
    })


def make_fake_cross_org_ado(
    *,
    origin_org: str = "org-external",
    propagated_constraints: list[str],
    max_child_dsal: int = 2,
    authorized_dsal: int = 3,  # must be strictly greater than max_child_dsal
) -> AuthorizedDecisionObject:
    """
    Build a synthetic cross-org ADO without going through evaluate().

    Useful for testing constraint validation in isolation — e.g. to supply
    non-standard or malformed propagated_constraints.
    """
    return AuthorizedDecisionObject(
        decision_id=str(uuid.uuid4()),
        authorized_dsal=authorized_dsal,
        authority="test-authority",
        expires_at=future(600),
        proposal_hash=hashlib.sha256(b"fake").hexdigest(),
        delegation_rules=DelegationRules(
            allowed_sub_decisions=["remediation", "configuration_change"],
            max_child_dsal=max_child_dsal,
            max_depth=3,
            max_children=10,
        ),
        signature=base64.b64encode(b"fake-sig").decode(),
        propagated_constraints=propagated_constraints,
        origin_org=origin_org,
        exec_context=ExecContext(
            decision_type=DecisionType.REMEDIATION,
            intent_binding=IntentBinding(
                intent="test",
                target="host:dev-01",
                scope_summary="test",
                expected_effect="test effect",
                reversibility=True,
            ),
        ),
    )
