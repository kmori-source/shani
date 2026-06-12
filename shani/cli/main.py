"""
shani/cli/main.py — Shani CLI entry point.

Commands:
    shani evaluate <proposal.json>   Evaluate a proposal JSON file
    shani check                      Quick end-to-end ADO issuance check
    shani demo                       HITL demo (auto-approve mode)
"""
from __future__ import annotations

import argparse
import sys

from .commands.evaluate import cmd_evaluate
from .commands.check import cmd_check
from .commands.demo import cmd_demo


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shani",
        description="Shani — Autonomous Decision Governance Layer CLI",
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version and exit"
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # evaluate
    p_eval = sub.add_parser(
        "evaluate",
        help="Evaluate a proposal JSON file and print the decision",
    )
    p_eval.add_argument(
        "proposal",
        metavar="proposal.json",
        help="Path to a DecisionProposal JSON file",
    )
    p_eval.add_argument(
        "--max-dsal", type=int, default=3,
        help="Maximum authorized D-SAL ceiling (default: 3)",
    )
    p_eval.add_argument(
        "--policy", metavar="policy.yaml",
        help="Path to authority/policy YAML file",
    )
    p_eval.add_argument(
        "--output", choices=["human", "json"], default="human",
        help="Output format (default: human)",
    )

    # check
    sub.add_parser(
        "check",
        help="Quick end-to-end ADO issuance and replay-prevention check",
    )

    # demo
    p_demo = sub.add_parser(
        "demo",
        help="Run HITL approval demo (auto-approve by default)",
    )
    p_demo.add_argument(
        "--mode", choices=["approve", "deny", "interactive"],
        default="approve",
        help="HITL response mode (default: approve)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from shani import __version__
        print(f"shani {__version__}")
        return 0

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "evaluate":
        return cmd_evaluate(args)
    if args.command == "check":
        return cmd_check()
    if args.command == "demo":
        return cmd_demo(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
