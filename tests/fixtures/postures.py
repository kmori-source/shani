"""
tests/fixtures/postures.py

Posture factory for the Shani test suites.

Provides:
  - make_user_posture(): UserPosture factory with sensible conformance defaults
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

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

from shani import UserPosture, PostureConstraints


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Posture factory
# ---------------------------------------------------------------------------


def make_user_posture(
    target_scope: str = "host:dev-.*",
    max_blast_radius: str = "limited",
    reversibility_required: bool = True,
    minimum_evidence: int = 1,
    posture_signature: str | None = "conformance-test-signature",
) -> UserPosture:
    return UserPosture(
        version="1.0",
        principal_id="conformance-tester@example.com",
        signed_at=_utcnow(),
        intent_statement="Conformance test posture.",
        simulation_ref="sim-conformance-001",
        constraints=PostureConstraints(
            target_scope=target_scope,
            max_blast_radius=max_blast_radius,
            reversibility_required=reversibility_required,
            minimum_evidence=minimum_evidence,
        ),
        posture_signature=posture_signature,
    )
