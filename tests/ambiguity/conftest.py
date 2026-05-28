"""
tests/ambiguity/conftest.py

pytest fixtures for the ambiguity test suite.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, os.path.join(_HERE, "../conformance"))

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

import pytest
from framework import ConformanceSuite


@pytest.fixture
def suite(request) -> ConformanceSuite:
    """ConformanceSuite fixture; fails the test if any check recorded a failure."""
    s = ConformanceSuite(request.node.name)
    yield s
    if s.report.failed_count > 0:
        s.report.print_summary()
        pytest.fail(
            f"{s.report.failed_count} conformance check(s) failed",
            pytrace=False,
        )
