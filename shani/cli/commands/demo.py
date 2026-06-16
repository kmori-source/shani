"""shani demo — Run the HITL approval demo."""

from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the HITL approval demo scenario."""
    mode = getattr(args, "mode", "approve")
    os.environ["SHANI_HITL_AUTO"] = mode

    scenario_path = (
        pathlib.Path(__file__).parent.parent.parent.parent
        / "examples"
        / "hitl_approval"
        / "scenario.py"
    )

    if not scenario_path.exists():
        print(f"  error: demo scenario not found at {scenario_path}")
        return 1

    print(f"\n  Running HITL demo in '{mode}' mode…\n")

    spec = importlib.util.spec_from_file_location("hitl_scenario", str(scenario_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.run()

    return 0
