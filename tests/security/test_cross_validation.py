"""
tests/security/test_cross_validation.py

Tests for EvidenceEvaluator cross-validation layer (issue #90).

Property being tested:
    EvidenceEvaluator with registered CrossValidators:
    - Agreement → quality_score boosted, cross_validated flag set
    - Conflict  → quality_score penalised, cross_validation_conflict flag set
    - No validators → identical to pre-#90 behaviour (backwards-compatible)
    - Validator exception → gracefully recorded as agreement=0.0, no crash
    - register_validator() adds validators after construction
    - explain() includes cross-validation results
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import warnings
warnings.filterwarnings("ignore")

from shani.schemas.decision import EvidenceItem
from shani.risk.evidence import (
    EvidenceEvaluator,
    CrossValidationResult,
    _CROSS_VALIDATION_AGREEMENT_BONUS,
    _CROSS_VALIDATION_CONFLICT_PENALTY,
)

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg: str) -> None:
    print(f"  {PASS} {msg}")


def fail(msg: str) -> None:
    _failures.append(msg)
    print(f"  {FAIL} {msg}")


# ---------------------------------------------------------------------------
# Mock CrossValidators
# ---------------------------------------------------------------------------

class _AlwaysAgreeValidator:
    """Agrees with every EvidenceItem (agreement=+1.0)."""

    @property
    def name(self) -> str:
        return "always_agree"

    def validate(self, item: EvidenceItem) -> CrossValidationResult:
        return CrossValidationResult(
            validator_name=self.name,
            item_source=item.source,
            agreement=1.0,
            notes="external source confirms",
        )


class _AlwaysConflictValidator:
    """Disagrees with every EvidenceItem (agreement=-1.0)."""

    @property
    def name(self) -> str:
        return "always_conflict"

    def validate(self, item: EvidenceItem) -> CrossValidationResult:
        return CrossValidationResult(
            validator_name=self.name,
            item_source=item.source,
            agreement=-1.0,
            notes="external source contradicts",
        )


class _NeutralValidator:
    """Returns neutral agreement (0.0) for all items."""

    @property
    def name(self) -> str:
        return "neutral"

    def validate(self, item: EvidenceItem) -> CrossValidationResult:
        return CrossValidationResult(
            validator_name=self.name,
            item_source=item.source,
            agreement=0.0,
            notes="no corroborating data",
        )


class _RaisingValidator:
    """Always raises — used to test error isolation."""

    @property
    def name(self) -> str:
        return "raising"

    def validate(self, item: EvidenceItem) -> CrossValidationResult:  # type: ignore[return]
        raise RuntimeError("network timeout")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_validators_backwards_compatible():
    """EvidenceEvaluator() with no validators behaves identically to pre-#90."""
    print("\n  ── No validators: backwards-compatible")
    ev = EvidenceEvaluator()
    items = [EvidenceItem(source="monitor", content="CPU high", confidence=0.8)]
    result = ev.evaluate(items)

    if result.cross_validation_results == []:
        ok("cross_validation_results is empty when no validators registered")
    else:
        fail(f"Expected empty cross_validation_results, got {result.cross_validation_results}")

    if "cross_validated" not in result.flags:
        ok("cross_validated flag absent when no validators registered")
    else:
        fail("cross_validated flag unexpectedly set with no validators")

    if "cross_validation_conflict" not in result.flags:
        ok("cross_validation_conflict flag absent when no validators registered")
    else:
        fail("cross_validation_conflict flag unexpectedly set with no validators")


def test_agreement_boosts_quality():
    """Agreeing cross-validators raise quality_score."""
    print("\n  ── Agreement: quality_score boosted")
    items = [
        EvidenceItem(source="edr", content="lateral movement", confidence=0.8),
        EvidenceItem(source="siem", content="anomalous traffic", confidence=0.9),
    ]

    # baseline (no validators)
    ev_base = EvidenceEvaluator()
    base_result = ev_base.evaluate(items)
    base_score = base_result.quality_score

    # with agreeing validator
    ev_agree = EvidenceEvaluator(cross_validators=[_AlwaysAgreeValidator()])
    agree_result = ev_agree.evaluate(items)
    agree_score = agree_result.quality_score

    if agree_score >= base_score:
        ok(f"agreement boosts quality_score: {base_score:.4f} → {agree_score:.4f}")
    else:
        fail(f"agreement should raise quality_score: base={base_score:.4f}, agree={agree_score:.4f}")

    if agree_result.flags.get("cross_validated"):
        ok("cross_validated flag set")
    else:
        fail("cross_validated flag NOT set after running validators")

    if "cross_validation_conflict" not in agree_result.flags:
        ok("cross_validation_conflict flag absent for pure agreement")
    else:
        fail("cross_validation_conflict flag wrongly set for pure agreement")

    if len(agree_result.cross_validation_results) == len(items):
        ok(f"{len(agree_result.cross_validation_results)} cross-validation results recorded")
    else:
        fail(
            f"Expected {len(items)} cross-validation results, "
            f"got {len(agree_result.cross_validation_results)}"
        )


def test_conflict_penalises_quality():
    """Conflicting cross-validators lower quality_score and set the conflict flag."""
    print("\n  ── Conflict: quality_score penalised, conflict flag set")
    items = [
        EvidenceItem(source="monitor", content="all clear", confidence=0.9),
    ]

    ev_base = EvidenceEvaluator()
    base_score = ev_base.evaluate(items).quality_score

    ev_conflict = EvidenceEvaluator(cross_validators=[_AlwaysConflictValidator()])
    conflict_result = ev_conflict.evaluate(items)
    conflict_score = conflict_result.quality_score

    if conflict_score < base_score:
        ok(f"conflict lowers quality_score: {base_score:.4f} → {conflict_score:.4f}")
    else:
        fail(f"conflict should lower quality_score: base={base_score:.4f}, conflict={conflict_score:.4f}")

    if conflict_result.flags.get("cross_validation_conflict"):
        ok("cross_validation_conflict flag set")
    else:
        fail("cross_validation_conflict flag NOT set for conflicting validator")

    if conflict_result.flags.get("cross_validated"):
        ok("cross_validated flag set")
    else:
        fail("cross_validated flag NOT set")


def test_neutral_validator_no_score_change():
    """Neutral validator (agreement=0.0) leaves quality_score unchanged."""
    print("\n  ── Neutral validator: no score change")
    items = [EvidenceItem(source="edr", content="ok", confidence=0.85)]

    ev_base = EvidenceEvaluator()
    base_score = ev_base.evaluate(items).quality_score

    ev_neutral = EvidenceEvaluator(cross_validators=[_NeutralValidator()])
    neutral_result = ev_neutral.evaluate(items)
    neutral_score = neutral_result.quality_score

    if abs(neutral_score - base_score) < 1e-6:
        ok(f"neutral validator leaves quality_score unchanged at {neutral_score:.4f}")
    else:
        fail(f"Expected unchanged score {base_score:.4f}, got {neutral_score:.4f}")

    if neutral_result.flags.get("cross_validated"):
        ok("cross_validated flag still set for neutral validator run")
    else:
        fail("cross_validated flag NOT set even though validators ran")

    if "cross_validation_conflict" not in neutral_result.flags:
        ok("cross_validation_conflict flag absent for neutral result")
    else:
        fail("cross_validation_conflict flag wrongly set for neutral result")


def test_raising_validator_isolated():
    """A validator that raises does not crash evaluate(); recorded as agreement=0.0."""
    print("\n  ── Raising validator: error isolated, agreement=0.0 recorded")
    items = [EvidenceItem(source="siem", content="alert", confidence=0.7)]

    ev = EvidenceEvaluator(cross_validators=[_RaisingValidator()])
    try:
        result = ev.evaluate(items)
    except Exception as exc:
        fail(f"evaluate() raised unexpectedly: {exc}")
        return

    ok("evaluate() did not raise despite faulty validator")

    if len(result.cross_validation_results) == 1:
        ok("error recorded as one cross-validation result")
    else:
        fail(f"Expected 1 result, got {len(result.cross_validation_results)}")

    cv = result.cross_validation_results[0]
    if cv["agreement"] == 0.0:
        ok("agreement=0.0 for errored validator")
    else:
        fail(f"Expected agreement=0.0, got {cv['agreement']}")

    if "validator error" in cv["notes"]:
        ok(f"error captured in notes: {cv['notes']}")
    else:
        fail(f"Expected 'validator error' in notes, got: {cv['notes']!r}")


def test_register_validator_post_construction():
    """register_validator() adds validators after __init__."""
    print("\n  ── register_validator(): post-construction registration")
    items = [EvidenceItem(source="edr", content="spike", confidence=0.8)]

    ev = EvidenceEvaluator()
    ev.register_validator(_AlwaysAgreeValidator())
    result = ev.evaluate(items)

    if result.flags.get("cross_validated"):
        ok("validator registered post-construction is executed")
    else:
        fail("cross_validated flag NOT set after register_validator()")

    if len(result.cross_validation_results) == 1:
        ok("one result from post-construction validator")
    else:
        fail(f"Expected 1 result, got {len(result.cross_validation_results)}")


def test_multiple_validators_combined():
    """Multiple validators: bonuses and penalties both applied."""
    print("\n  ── Multiple validators: combined effect")
    items = [EvidenceItem(source="monitor", content="disk full", confidence=0.75)]

    ev_base = EvidenceEvaluator()
    base_score = ev_base.evaluate(items).quality_score

    # one agree + one conflict → net penalty (_AGREEMENT_BONUS < _CONFLICT_PENALTY)
    ev_mixed = EvidenceEvaluator(cross_validators=[
        _AlwaysAgreeValidator(),
        _AlwaysConflictValidator(),
    ])
    mixed_result = ev_mixed.evaluate(items)
    mixed_score = mixed_result.quality_score

    expected_delta = _CROSS_VALIDATION_AGREEMENT_BONUS - _CROSS_VALIDATION_CONFLICT_PENALTY
    expected_score = max(0.0, min(1.0, base_score + expected_delta))
    if abs(mixed_score - expected_score) < 1e-4:
        ok(f"combined score correct: {base_score:.4f} + ({expected_delta:+.2f}) = {mixed_score:.4f}")
    else:
        fail(f"Expected combined score ≈{expected_score:.4f}, got {mixed_score:.4f}")

    if mixed_result.flags.get("cross_validation_conflict"):
        ok("cross_validation_conflict flag set (conflict present)")
    else:
        fail("cross_validation_conflict flag NOT set despite conflict validator")

    if len(mixed_result.cross_validation_results) == 2:
        ok("2 results from 2 validators")
    else:
        fail(f"Expected 2 results, got {len(mixed_result.cross_validation_results)}")


def test_explain_includes_cross_validation():
    """explain() output contains cross-validation section."""
    print("\n  ── explain(): cross-validation results included")
    items = [EvidenceItem(source="edr", content="alert", confidence=0.9)]

    ev = EvidenceEvaluator(cross_validators=[_AlwaysAgreeValidator()])
    result = ev.evaluate(items)
    explanation = result.explain()

    if "cross_validation" in explanation:
        ok("explain() contains 'cross_validation' section")
    else:
        fail("explain() does not mention cross_validation")

    if "always_agree" in explanation:
        ok("validator name appears in explain() output")
    else:
        fail("validator name not found in explain() output")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 64)
    print("  EvidenceEvaluator Cross-Validation Tests (issue #90)")
    print("=" * 64)

    test_no_validators_backwards_compatible()
    test_agreement_boosts_quality()
    test_conflict_penalises_quality()
    test_neutral_validator_no_score_change()
    test_raising_validator_isolated()
    test_register_validator_post_construction()
    test_multiple_validators_combined()
    test_explain_includes_cross_validation()

    print("\n" + "=" * 64)
    if _failures:
        print(f"  FAILED: {len(_failures)} issue(s)")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All cross-validation tests passed.")
        print()
        print("  Design summary:")
        print("  - CrossValidator protocol: pluggable external source interface")
        print("  - Agreement (+agreement ≥ 0.3)  → +0.05 quality bonus per call")
        print("  - Conflict  (agreement ≤ −0.3) → −0.15 quality penalty + flag")
        print("  - Validator errors isolated; recorded as agreement=0.0")
        print("  - No validators registered → zero behaviour change (backwards-compat)")
    print("=" * 64)
