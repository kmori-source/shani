"""
tests/conformance/runner.py

Shani Conformance Test Runner.

Runs both MUST FAIL and MUST PASS suites, prints a combined report,
and optionally writes a JSON report to disk.

Usage:
    python -m tests.conformance.runner
    python -m tests.conformance.runner --json report.json
    python tests/conformance/runner.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


def _load_pydantic_shim() -> None:
    """Ensure pydantic is importable (shim for environments without it)."""
    try:
        import pydantic  # noqa: F401

        return
    except ImportError:
        pass
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


_load_pydantic_shim()

import warnings

warnings.filterwarnings("ignore")

from .test_must_fail import run as run_must_fail
from .test_must_pass import run as run_must_pass
from .framework import ConformanceReport


def run_all(json_output_path: str | None = None) -> int:
    """
    Run the full conformance suite.

    Returns:
        0  — all tests passed
        1  — one or more failures
    """
    started = datetime.now(tz=timezone.utc)

    print("\n" + "=" * 60)
    print("  Shani Conformance Test Suite")
    print(f"  Started: {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print("=" * 60)

    must_fail_suite = run_must_fail()
    must_pass_suite = run_must_pass()

    # Combined summary
    all_results = must_fail_suite.report.results + must_pass_suite.report.results
    total = len(all_results)
    passed = sum(1 for r in all_results if r.passed)
    failed = total - passed

    finished = datetime.now(tz=timezone.utc)
    duration = (finished - started).total_seconds()

    print("\n" + "=" * 60)
    print("  CONFORMANCE SUMMARY")
    print("─" * 60)
    print(
        f"  MUST FAIL : {must_fail_suite.report.passed_count}/{must_fail_suite.report.total} passed"
    )
    print(
        f"  MUST PASS : {must_pass_suite.report.passed_count}/{must_pass_suite.report.total} passed"
    )
    print(f"  TOTAL     : {passed}/{total} passed  ({failed} failed)")
    print(f"  Duration  : {duration:.2f}s")

    if failed:
        print("\n  FAILURES:")
        for r in all_results:
            if not r.passed:
                print(f"    [{r.category.value}] {r.test_id}")
                print(f"      {r.description}")
                if r.detail:
                    print(f"      Detail: {r.detail}")
                if r.spec_ref:
                    print(f"      Spec: {r.spec_ref}")
    print("=" * 60)

    if json_output_path:
        report_data = {
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round(duration, 3),
            "total": total,
            "passed": passed,
            "failed": failed,
            "suites": {
                "must_fail": json.loads(must_fail_suite.report.to_json()),
                "must_pass": json.loads(must_pass_suite.report.to_json()),
            },
        }
        with open(json_output_path, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n  JSON report written to: {json_output_path}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Shani Conformance Test Runner")
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="Write structured JSON report to this file",
        default=None,
    )
    args = parser.parse_args()
    sys.exit(run_all(json_output_path=args.json))
