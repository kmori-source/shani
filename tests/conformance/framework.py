"""
tests/conformance/framework.py

Conformance Test Framework for Shani.

Building blocks:
    ConformanceCategory  — MUST_FAIL or MUST_PASS
    ConformanceResult    — outcome of a single conformance check
    ConformanceReport    — aggregated results with structured JSON output
    ConformanceSuite     — base class that suites inherit from

Usage in a test module:
    suite = ConformanceSuite("MUST_FAIL: ADO expiry")
    suite.assert_must_fail("expired_ado", result, "ADO must be rejected when expired")
    suite.report.print_summary()
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# ---------------------------------------------------------------------------
# Category
# ---------------------------------------------------------------------------


class ConformanceCategory(str, Enum):
    MUST_FAIL = "MUST_FAIL"
    MUST_PASS = "MUST_PASS"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class ConformanceResult:
    test_id: str
    category: ConformanceCategory
    passed: bool
    description: str
    detail: str = ""
    spec_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "category": self.category.value,
            "passed": self.passed,
            "description": self.description,
            "detail": self.detail,
            "spec_ref": self.spec_ref,
        }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


PASS_MARK = "\033[92m✓\033[0m"
FAIL_MARK = "\033[91m✗\033[0m"
SKIP_MARK = "\033[93m⊘\033[0m"


@dataclass
class ConformanceReport:
    suite_name: str
    results: list[ConformanceResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def add(self, result: ConformanceResult) -> None:
        self.results.append(result)
        mark = PASS_MARK if result.passed else FAIL_MARK
        detail_str = f"\n      {result.detail}" if result.detail else ""
        print(f"  {mark} [{result.category.value}] {result.description}{detail_str}")

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def failures(self) -> list[ConformanceResult]:
        return [r for r in self.results if not r.passed]

    def print_summary(self) -> None:
        width = 60
        print(f"\n{'=' * width}")
        print(f"  {self.suite_name}")
        print(f"{'─' * width}")
        print(f"  Total: {self.total}  Passed: {self.passed_count}  Failed: {self.failed_count}")
        if self.failures:
            print(f"\n  Failures:")
            for f in self.failures:
                print(f"    • [{f.category.value}] {f.test_id}: {f.description}")
                if f.detail:
                    print(f"      {f.detail}")
        print(f"{'=' * width}")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "suite": self.suite_name,
                "started_at": self.started_at.isoformat(),
                "total": self.total,
                "passed": self.passed_count,
                "failed": self.failed_count,
                "results": [r.to_dict() for r in self.results],
            },
            indent=indent,
        )

    def assert_all_passed(self) -> None:
        """Call at the end of a suite; exits with code 1 if any failures."""
        if self.failed_count:
            sys.exit(1)


# ---------------------------------------------------------------------------
# Suite base
# ---------------------------------------------------------------------------


class ConformanceSuite:
    """
    Base class for conformance test suites.

    Subclass and implement test methods, calling self.must_fail() /
    self.must_pass() to record results.
    """

    def __init__(self, name: str) -> None:
        self.report = ConformanceReport(suite_name=name)

    def _section(self, title: str) -> None:
        print(f"\n{'─' * 60}\n  {title}\n{'─' * 60}")

    def must_fail(
        self,
        test_id: str,
        condition: bool,
        description: str,
        detail: str = "",
        spec_ref: str = "",
    ) -> ConformanceResult:
        """
        Assert that an operation was correctly rejected.

        condition: True  → implementation correctly rejected (PASS)
                   False → implementation did not reject  (FAIL — security gap)
        """
        result = ConformanceResult(
            test_id=test_id,
            category=ConformanceCategory.MUST_FAIL,
            passed=condition,
            description=description,
            detail=detail,
            spec_ref=spec_ref,
        )
        self.report.add(result)
        return result

    def must_pass(
        self,
        test_id: str,
        condition: bool,
        description: str,
        detail: str = "",
        spec_ref: str = "",
    ) -> ConformanceResult:
        """
        Assert that a valid operation was correctly accepted.

        condition: True  → implementation correctly accepted (PASS)
                   False → implementation wrongly rejected (FAIL — over-blocking)
        """
        result = ConformanceResult(
            test_id=test_id,
            category=ConformanceCategory.MUST_PASS,
            passed=condition,
            description=description,
            detail=detail,
            spec_ref=spec_ref,
        )
        self.report.add(result)
        return result
