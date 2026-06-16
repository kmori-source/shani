"""
tests/ambiguity/fixtures.py

Shared factories for the ambiguity test suite.

Tests cover T15 (Ambiguity Escalation) and related boundary conditions.
All factories accept keyword overrides for targeted field variation.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

    _spec = _iu.spec_from_file_location(
        "_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"),
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings

warnings.filterwarnings("ignore")

from shani import (
    BlastRadius,
    DecisionType,
    DeniedDecision,
    PostureConstraints,
    ShaniEvaluator,
    StaticAuthorityProvider,
    UserPosture,
)
from shani.authority.policy import AgentIdentity, DecisionPolicyProvider
from shani.schemas.decision import (
    AuthorizedDecisionObject,
    DecisionProposal,
    DecisionScope,
    DelegationRules,
    EvidenceItem,
)
from shani.schemas.posture import PostureOutcome, PostureRefinementRequest
from shani.posture.engine import PostureEngine
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
# Agent registry
# ---------------------------------------------------------------------------

AMBIGUITY_AGENTS: dict[str, AgentIdentity] = {
    "agent/ambiguity": AgentIdentity(
        agent_id="agent/ambiguity",
        granted_dsal=3,
        allowed_decision_types=frozenset(["remediation", "data_access", "configuration_change"]),
    ),
    "agent/low": AgentIdentity(
        agent_id="agent/low",
        granted_dsal=1,
        allowed_decision_types=frozenset(["remediation"]),
    ),
    "agent/high": AgentIdentity(
        agent_id="agent/high",
        granted_dsal=4,
        allowed_decision_types=frozenset(
            [
                "remediation",
                "data_access",
                "configuration_change",
                "policy_update",
                "network_action",
            ]
        ),
    ),
}


# ---------------------------------------------------------------------------
# Evaluator factory
# ---------------------------------------------------------------------------


def make_evaluator(
    *,
    max_dsal: int = 3,
    user_posture: UserPosture | None = None,
    nonce_store: InMemoryNonceStore | None = None,
    agents: dict[str, AgentIdentity] | None = None,
) -> ShaniEvaluator:
    policy = DecisionPolicyProvider(
        agent_registry=agents if agents is not None else AMBIGUITY_AGENTS,
    )
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=max_dsal),
        decision_policy=policy,
        user_posture=user_posture,
        nonce_store=nonce_store if nonce_store is not None else InMemoryNonceStore(),
    )


# ---------------------------------------------------------------------------
# Posture factory
# ---------------------------------------------------------------------------


def make_posture(
    *,
    target_scope: str = r"host:dev-.*",
    max_blast_radius: str = "limited",
    reversibility_required: bool = True,
    minimum_evidence: int = 1,
    principal_id: str = "tester@example.com",
    posture_signature: str | None = "ambiguity-test-sig",
) -> UserPosture:
    return UserPosture(
        version="1.0",
        principal_id=principal_id,
        signed_at=utcnow(),
        intent_statement="Ambiguity test posture.",
        simulation_ref="sim-ambiguity-001",
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
        proposed_by="agent/ambiguity",
        description="Isolate dev host after alert",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="CPU spike", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=future(300),
    )
    defaults.update(kwargs)
    return DecisionProposal(**defaults)


# ---------------------------------------------------------------------------
# PostureEngine helper
# ---------------------------------------------------------------------------


def evaluate_posture(
    proposal: DecisionProposal,
    posture: UserPosture,
) -> tuple[PostureOutcome, PostureRefinementRequest | None]:
    engine = PostureEngine(user_posture=posture)
    return engine.evaluate(proposal)
