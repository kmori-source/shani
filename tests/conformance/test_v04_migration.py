"""
tests/conformance/test_v04_migration.py

Migration wrapper: v0.4 conformance tests → conformance framework.

Integrates tests/security/test_v04_conformance.py into the structured
conformance suite without duplicating or removing the originals.

The existing tests remain runnable independently at:
    python tests/security/test_v04_conformance.py

This module re-exposes them as a ConformanceSuite so the runner can
include their results in the unified report.
"""
from __future__ import annotations

import os
import sys
from io import StringIO

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

from .framework import ConformanceSuite

# ---------------------------------------------------------------------------
# Import original test functions
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_SECURITY_DIR = os.path.join(_HERE, "..", "security")

sys.path.insert(0, os.path.dirname(_HERE))

from tests.security.test_v04_conformance import (
    test_posture_registration,
    test_posture_engine_layer1,
    test_posture_ambiguous_produces_refinement,
    test_refinement_request_is_not_denied_decision,
    test_cross_org_propagated_constraints,
    test_posture_simulation,
    test_org_policy_absolute_constraints,
    _failures as _v04_failures,
)


# ---------------------------------------------------------------------------
# Adapter: run v0.4 tests, capture failures, emit ConformanceResult entries
# ---------------------------------------------------------------------------


def run_v04_as_conformance_suite() -> ConformanceSuite:
    """
    Run all v0.4 conformance tests and report outcomes via ConformanceSuite.

    The v0.4 tests use a custom ok()/fail() framework that accumulates failures
    in a module-level list.  This adapter runs each test function, captures
    whether it added new failures, and emits a MUST_PASS result per test.
    """
    import tests.security.test_v04_conformance as _mod

    suite = ConformanceSuite("v0.4 Conformance Tests (migrated from tests/security/)")

    def _run_test(name: str, fn) -> None:
        before = len(_mod._failures)
        try:
            fn()
            after = len(_mod._failures)
            new_failures = _mod._failures[before:]
            passed = len(new_failures) == 0
            detail = "; ".join(new_failures) if new_failures else ""
        except Exception as exc:
            passed = False
            detail = f"Exception: {exc}"

        suite.must_pass(
            test_id=f"v04:{name}",
            condition=passed,
            description=f"v0.4 conformance: {name}",
            detail=detail,
            spec_ref="SPEC §8.9",
        )

    tests_to_run = [
        ("posture_registration",                    test_posture_registration),
        ("posture_engine_layer1",                   test_posture_engine_layer1),
        ("posture_ambiguous_produces_refinement",   test_posture_ambiguous_produces_refinement),
        ("refinement_request_is_not_denied_decision", test_refinement_request_is_not_denied_decision),
        ("cross_org_propagated_constraints",        test_cross_org_propagated_constraints),
        ("posture_simulation",                      test_posture_simulation),
        ("org_policy_absolute_constraints",         test_org_policy_absolute_constraints),
    ]

    suite._section("v0.4 Conformance Tests (migrated)")
    for name, fn in tests_to_run:
        _run_test(name, fn)

    return suite


if __name__ == "__main__":
    print("=" * 60)
    print("  Shani v0.4 Conformance Tests (migrated)")
    print("=" * 60)

    suite = run_v04_as_conformance_suite()
    suite.report.print_summary()
    suite.report.assert_all_passed()
