"""
tests/fixtures/proposals.py

Proposal factory for the Shani test suites.

Provides:
  - make_proposal(): DecisionProposal factory with sensible conformance defaults
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

from shani import DecisionType, BlastRadius, DecisionScope, EvidenceItem
from shani.schemas.decision import DecisionProposal


def _future(seconds: int = 300) -> datetime:
    return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Proposal factory
# ---------------------------------------------------------------------------


def make_proposal(**kwargs) -> DecisionProposal:
    defaults: dict = dict(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="agent/conformance",
        description="Isolate dev host after alert",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="CPU spike 99%", confidence=0.95)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=_future(300),
    )
    defaults.update(kwargs)
    return DecisionProposal(**defaults)
