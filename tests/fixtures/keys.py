"""
tests/fixtures/keys.py

Signing keys, test credentials, and evaluator factory for the Shani test suites.

Provides:
  - Time helpers: utcnow(), future(), past()
  - CONFORMANCE_AGENTS: agent identity registry
  - make_evaluator(): ShaniEvaluator factory
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
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

from shani import ShaniEvaluator, StaticAuthorityProvider, UserPosture
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity, OrgPolicy
from shani.schemas.state import DISStateMachine
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
# Agent registry — test credentials used across conformance tests
# ---------------------------------------------------------------------------

CONFORMANCE_AGENTS: dict[str, AgentIdentity] = {
    "agent/conformance": AgentIdentity(
        agent_id="agent/conformance",
        granted_dsal=3,
        allowed_decision_types=frozenset(["remediation", "data_access", "policy_update"]),
    ),
    "agent/low-dsal": AgentIdentity(
        agent_id="agent/low-dsal",
        granted_dsal=1,
        allowed_decision_types=frozenset(["remediation"]),
    ),
}


# ---------------------------------------------------------------------------
# Evaluator factory
# ---------------------------------------------------------------------------


def make_evaluator(
    max_dsal: int = 3,
    user_posture: UserPosture | None = None,
    dis_machine: DISStateMachine | None = None,
    nonce_store: InMemoryNonceStore | None = None,
    org_id: str | None = None,
    org_policy: OrgPolicy | None = None,
) -> ShaniEvaluator:
    policy = DecisionPolicyProvider(
        agent_registry=CONFORMANCE_AGENTS,
        org_policy=org_policy,
    )
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=max_dsal),
        decision_policy=policy,
        user_posture=user_posture,
        dis_machine=dis_machine,
        nonce_store=nonce_store if nonce_store is not None else InMemoryNonceStore(),
        org_id=org_id,
    )
