"""
tests/fixtures/ados.py

ADO (AuthorizedDecisionObject) factories for the Shani test suites.

Provides:
  - make_valid_ado(): evaluate proposal and return ADO
  - make_expired_ado(): return an ADO with expires_at in the past
  - make_cross_org_ado(): return a cross-org ADO with propagated_constraints
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, _HERE)

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

from shani import ShaniEvaluator, DeniedDecision, DecisionType
from shani.schemas.decision import AuthorizedDecisionObject, DecisionProposal

from proposals import make_proposal


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _past(seconds: int = 10) -> datetime:
    return _utcnow() - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# ADO helpers
# ---------------------------------------------------------------------------


def make_valid_ado(evaluator: ShaniEvaluator, proposal: DecisionProposal) -> AuthorizedDecisionObject:
    """Evaluate a proposal and return the ADO, raising if denied."""
    result = evaluator.evaluate(proposal)
    if isinstance(result, DeniedDecision):
        raise RuntimeError(f"Unexpected denial in fixture: {result.reason}")
    if not isinstance(result, AuthorizedDecisionObject):
        raise RuntimeError(f"Unexpected result type: {type(result)}")
    return result


def make_expired_ado(evaluator: ShaniEvaluator) -> AuthorizedDecisionObject:
    """
    Return an ADO whose expires_at is in the past.

    The ADO is first issued validly, then copied with expires_at set to a past
    timestamp without updating the signature — this is intentionally invalid.
    """
    proposal = make_proposal()
    ado = make_valid_ado(evaluator, proposal)
    expired_at = _past(seconds=5)
    return ado.model_copy(update={
        "issued_at": _past(seconds=60),
        "expires_at": expired_at,
    })


def make_cross_org_ado(
    evaluator: ShaniEvaluator,
    with_propagated_constraints: bool = True,
) -> AuthorizedDecisionObject:
    """Return a cross-org ADO (origin_org set). Optionally without propagated_constraints."""
    proposal = make_proposal(
        decision_type=DecisionType.REMEDIATION,
        origin_org="org-alpha",
    )
    ado = make_valid_ado(evaluator, proposal)
    constraints = ["target_scope:domestic-only", "max_blast_radius:limited"] if with_propagated_constraints else []
    return ado.model_copy(update={
        "origin_org": "org-alpha",
        "propagated_constraints": constraints,
    })
