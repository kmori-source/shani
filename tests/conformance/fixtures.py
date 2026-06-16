"""
tests/conformance/fixtures.py

Shared test fixtures for the Shani conformance suite.

All factories are imported from tests/fixtures/ and re-exported here so that
existing conformance tests (which add this directory to sys.path and import
from 'fixtures') continue to work unchanged.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

_FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../fixtures")
sys.path.insert(0, _FIXTURES_DIR)

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

# Re-export everything from the new tests/fixtures/ modules
from keys import utcnow, future, past, CONFORMANCE_AGENTS, make_evaluator
from proposals import make_proposal
from ados import make_valid_ado, make_expired_ado, make_cross_org_ado
from postures import make_user_posture

__all__ = [
    "utcnow",
    "future",
    "past",
    "CONFORMANCE_AGENTS",
    "make_evaluator",
    "make_proposal",
    "make_valid_ado",
    "make_expired_ado",
    "make_cross_org_ado",
    "make_user_posture",
]
