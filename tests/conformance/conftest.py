"""
tests/conformance/conftest.py

pytest fixtures for the Shani conformance test suite.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# tests/conformance/conftest.py に追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../fixtures"))

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

import pytest
from framework import ConformanceSuite


@pytest.fixture
def suite(request) -> ConformanceSuite:
    """Provide a ConformanceSuite instance for conformance test functions.

    Fails the pytest test if any conformance check recorded a failure.
    """
    s = ConformanceSuite(request.node.name)
    yield s
    if s.report.failed_count > 0:
        s.report.print_summary()
        pytest.fail(
            f"{s.report.failed_count} conformance check(s) failed",
            pytrace=False,
        )
