"""
tests/security/test_dsal_calculator.py

Tests for DSALCalculator.
Verifies that each modifier correctly raises the effective D-SAL.

Important: Agents do not declare their own D-SAL.
     Shani computes it automatically from proposal context.
"""
from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location("_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"))
    _mod = _iu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel","Field","field_validator","model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings; warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone
from shani.authority.dsal_calculator import DSALCalculator
from shani.schemas.decision import (
    DecisionProposal, DecisionType, BlastRadius, DecisionScope, EvidenceItem
)

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []

def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f": {d}" if d else ""))
def section(t): print(f"\n  ── {t} ──────────────────────────────────────")

def future(): return datetime.now(tz=timezone.utc) + timedelta(minutes=5)

def make_proposal(**overrides) -> DecisionProposal:
    """Create a base low-risk proposal."""
    defaults = dict(
        decision_type  = DecisionType.REMEDIATION,
        proposed_by    = "test-agent/v1",
        description    = "test action",
        target         = "host:dev-01",        # not production
        scope          = DecisionScope(),
        evidence       = [EvidenceItem(source="monitor", content="CPU high", confidence=0.9)],
        confidence     = 0.9,
        reversibility  = True,
        blast_radius   = BlastRadius.LIMITED,
        delegation     = False,
        expires_at     = future(),
    )
    defaults.update(overrides)
    return DecisionProposal(**defaults)

calc = DSALCalculator()


def test_base_no_modifiers():
    section("base only (no modifiers)")
    p = make_proposal()
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 1:
        fail(f"Expected 1, got {r.effective}", r.explain())
    else:
        ok(f"base=1, no modifiers → effective=1")
    assert r.total_adjustment == 0


def test_blast_radius_significant():
    section("blast_radius modifiers")
    p = make_proposal(blast_radius=BlastRadius.SIGNIFICANT)
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 2:
        fail(f"SIGNIFICANT: expected 2, got {r.effective}", r.explain())
    else:
        ok(f"blast_radius=SIGNIFICANT → +1 → effective=2")

    p2 = make_proposal(blast_radius=BlastRadius.CRITICAL)
    r2 = calc.calculate(p2, base_dsal=1)
    if r2.effective != 3:
        fail(f"CRITICAL: expected 3, got {r2.effective}", r2.explain())
    else:
        ok(f"blast_radius=CRITICAL → +2 → effective=3")


def test_irreversible():
    section("reversibility=False")
    p = make_proposal(reversibility=False)
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 2:
        fail(f"Expected 2, got {r.effective}", r.explain())
    else:
        ok(f"reversibility=False → +1 → effective=2")


def test_prod_target():
    section("Production environment targets")
    for keyword in ["prod", "production", "live", "prd"]:
        p = make_proposal(target=f"host:{keyword}-db-01")
        r = calc.calculate(p, base_dsal=1)
        if r.effective != 2:
            fail(f"target with '{keyword}': expected 2, got {r.effective}")
        else:
            ok(f"target contains '{keyword}' → +1 → effective=2")


def test_no_evidence():
    section("no evidence")
    p = make_proposal(evidence=[])
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 2:
        fail(f"Expected 2, got {r.effective}", r.explain())
    else:
        ok(f"evidence=[] → +1 → effective=2")


def test_low_confidence_evidence():
    section("low-confidence evidence")
    p = make_proposal(evidence=[
        EvidenceItem(source="s", content="uncertain", confidence=0.4),
        EvidenceItem(source="s2", content="also uncertain", confidence=0.5),
    ])
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 2:
        fail(f"Expected 2, got {r.effective}", r.explain())
    else:
        ok(f"avg_confidence=0.45 < 0.6 → +1 → effective=2")


def test_delegation():
    section("delegation=True")
    p = make_proposal(delegation=True)
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 2:
        fail(f"Expected 2, got {r.effective}", r.explain())
    else:
        ok(f"delegation=True → +1 → effective=2")


def test_low_agent_confidence():
    section("low agent confidence")
    p = make_proposal(confidence=0.3)
    r = calc.calculate(p, base_dsal=1)
    if r.effective != 2:
        fail(f"Expected 2, got {r.effective}", r.explain())
    else:
        ok(f"confidence=0.3 < 0.5 → +1 → effective=2")


def test_stacked_modifiers():
    section("stacked modifiers (capped at 4)")
    p = make_proposal(
        target         = "host:prod-critical-01",  # +1 (prod)
        blast_radius   = BlastRadius.SIGNIFICANT,   # +1
        reversibility  = False,                     # +1
        evidence       = [],                        # +1
        confidence     = 0.3,                       # +1
    )
    r = calc.calculate(p, base_dsal=1)
    # base=1 + prod(+1) + significant(+1) + irreversible(+1) + no_evidence(+1) + low_conf(+1) = 6 → cap 4
    if r.effective != 4:
        fail(f"Expected 4 (capped), got {r.effective}", r.explain())
    else:
        ok(f"5 modifiers stacked on base=1 → capped at 4")
    assert r.total_adjustment >= 4, f"total_adjustment should be >= 4, got {r.total_adjustment}"
    ok(f"total_adjustment={r.total_adjustment} (before cap)")


def test_cap_at_4():
    section("D-SAL does not exceed 4")
    p = make_proposal(
        target       = "host:prod-01",
        blast_radius = BlastRadius.CRITICAL,
        reversibility = False,
        evidence     = [],
        confidence   = 0.2,
        delegation   = True,
    )
    r = calc.calculate(p, base_dsal=3)
    if r.effective > 4:
        fail(f"Should be capped at 4, got {r.effective}")
    else:
        ok(f"base=3 + many modifiers → capped at 4 (got {r.effective})")


def test_explain_output():
    section("explain() output")
    p = make_proposal(
        target       = "host:prod-01",
        blast_radius = BlastRadius.SIGNIFICANT,
        evidence     = [],
    )
    r = calc.calculate(p, base_dsal=1)
    explanation = r.explain()
    assert "base" in explanation
    assert "+1" in explanation
    ok("explain() output contains base and modifiers")
    print(f"\n    {explanation.replace(chr(10), chr(10) + '    ')}")


def test_agent_cannot_reduce_dsal():
    section("Verify agent cannot lower D-SAL")
    # high-risk context
    high_risk = make_proposal(
        target       = "host:prod-01",
        blast_radius = BlastRadius.SIGNIFICANT,
        evidence     = [],
    )
    r_high = calc.calculate(high_risk, base_dsal=1)
    ok(f"high-risk context: effective={r_high.effective} (ignored even if agent declared 1)")
    assert r_high.effective >= 2, "high-risk should be at least 2"

    # even if an agent could declare requested_dsal=0, the result would not change
    # (impossible because requested_dsal field does not exist in DecisionProposal)
    low_risk = make_proposal(
        target       = "host:dev-01",
        blast_radius = BlastRadius.ISOLATED,
        evidence     = [EvidenceItem(source="s", content="clear", confidence=0.95)],
        confidence   = 0.95,
    )
    r_low = calc.calculate(low_risk, base_dsal=1)
    ok(f"low-risk context: effective={r_low.effective} (legitimately low)")
    assert r_low.effective == 1


if __name__ == "__main__":
    print("=" * 57)
    print("  DSALCalculator Tests")
    print("  Agents do not declare their own D-SAL")
    print("  Shani computes D-SAL automatically from context")
    print("=" * 57)

    test_base_no_modifiers()
    test_blast_radius_significant()
    test_irreversible()
    test_prod_target()
    test_no_evidence()
    test_low_confidence_evidence()
    test_delegation()
    test_low_agent_confidence()
    test_stacked_modifiers()
    test_cap_at_4()
    test_explain_output()
    test_agent_cannot_reduce_dsal()

    print("\n" + "=" * 57)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures: print(f"    • {f}")
        import sys; sys.exit(1)
    else:
        print("  All tests passed\n")
        print("  Modifier list (each raises effective D-SAL when applied):")
        print("    blast_radius=SIGNIFICANT  → +1")
        print("    blast_radius=CRITICAL     → +2")
        print("    reversibility=False       → +1")
        print("    target contains prod/live/prd → +1")
        print("    no evidence             → +1")
        print("    evidence avg confidence < 0.6   → +1")
        print("    delegation=True           → +1")
        print("    confidence < 0.5          → +1")
        print("    cap: 4")
    print("=" * 57)
