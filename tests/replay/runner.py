"""
tests/replay/runner.py

Replay Attack Test Suite Runner.

Runs the full replay test suite, prints a structured report, and optionally
writes a JSON report to disk.

Usage:
    python tests/replay/runner.py
    python tests/replay/runner.py --json report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, os.path.join(_HERE, "../conformance"))
sys.path.insert(0, _HERE)


def _load_pydantic_shim() -> None:
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

from test_replay import run as run_replay


def run_all(json_output_path: str | None = None) -> int:
    """
    Run the full replay attack test suite.

    Returns:
        0  — all tests passed
        1  — one or more failures
    """
    started = datetime.now(tz=timezone.utc)

    print("\n" + "=" * 60)
    print("  Shani Replay Attack Test Suite")
    print(f"  Started: {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print("=" * 60)

    suite = run_replay()
    suite.report.print_summary()

    finished = datetime.now(tz=timezone.utc)
    duration = (finished - started).total_seconds()

    print(f"\n  Duration: {duration:.2f}s")
    print("=" * 60)

    if json_output_path:
        report_data = {
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round(duration, 3),
            "total": suite.report.total,
            "passed": suite.report.passed_count,
            "failed": suite.report.failed_count,
            "suite": json.loads(suite.report.to_json()),
        }
        with open(json_output_path, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n  JSON report written to: {json_output_path}")

    return 0 if suite.report.failed_count == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shani Replay Attack Test Runner")
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="Write structured JSON report to this file",
        default=None,
    )
    args = parser.parse_args()
    sys.exit(run_all(json_output_path=args.json))
