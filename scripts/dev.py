#!/usr/bin/env python3
"""
scripts/dev.py — Shani development runner.

Usage:
    python scripts/dev.py          # end-to-end check + all tests
    python scripts/dev.py check    # quick ADO issuance check only
    python scripts/dev.py tests    # all test suites
    python scripts/dev.py demo     # HITL demo (auto-approve)
    python scripts/dev.py signature  # signature coverage tests only

Requirements (all pure Python or widely available):
    Python >= 3.11
    pyyaml        (pip install pyyaml)
    cryptography  (pip install cryptography)  — optional, for Ed25519
    pydantic      (pip install "pydantic>=2.5") — optional, shim used if absent
"""
from __future__ import annotations

import os
import sys
import subprocess
import types

# Project root: one level up from this script's directory (scripts/)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Step 1: inject pydantic shim BEFORE any shani import ────────────────────
# Must happen here before `import shani` triggers shani/__init__.py which
# imports pydantic immediately.
try:
    import pydantic  # noqa: F401
except ImportError:
    import importlib.util
    import pathlib
    _compat_path = pathlib.Path(_ROOT) / "shani" / "_compat.py"
    _spec = importlib.util.spec_from_file_location("_compat", _compat_path)
    _compat = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_compat)

    _shim = types.ModuleType("pydantic")
    _shim.BaseModel       = _compat.BaseModel
    _shim.Field           = _compat.Field
    _shim.field_validator = _compat.field_validator
    _shim.model_validator = _compat.model_validator
    sys.modules["pydantic"] = _shim
    print("  [pydantic shim active — install pydantic>=2.5 for production]\n")

# ── Step 2: now safe to import shani ────────────────────────────────────────
sys.path.insert(0, _ROOT)


def header(t):
    print(f"\n{'═'*60}\n  {t}\n{'═'*60}")


def run_file(path: str) -> bool:
    return subprocess.run([sys.executable, path]).returncode == 0


def cmd_check():
    header("Quick End-to-End Check")
    from datetime import datetime, timedelta, timezone
    from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius, DeniedDecision
    from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
    from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

    policy = DecisionPolicyProvider(agent_registry={
        "test-agent/v1": AgentIdentity(
            agent_id="test-agent/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(["remediation"]),
        )
    })
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=policy,
    )
    proposal = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="test-agent/v1",
        description="Restart nginx on prod-web-01",
        target="host:prod-web-01",
        scope=DecisionScope(asset_ids=["host:prod-web-01"]),
        evidence=[EvidenceItem(source="monitor", content="CPU 99% for 5m", confidence=0.9)],
        confidence=0.9,
        requested_dsal=2,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
    )

    result = evaluator.evaluate(proposal)
    if isinstance(result, DeniedDecision):
        print(f"  ✗ Unexpected denial: {result.reason}"); return False

    ado = result
    print(f"  ✓ ADO issued")
    print(f"    decision_id    : {ado.decision_id[:8]}…")
    print(f"    proposal_hash  : {ado.proposal_hash[:16]}…")
    print(f"    authority      : {ado.authority}")
    print(f"    authorized_dsal: {ado.authorized_dsal}")
    print(f"    nonce          : {ado.nonce[:16]}…")
    print(f"    issued_at      : {ado.issued_at.strftime('%H:%M:%S UTC')}")
    print(f"    expires_at     : {ado.expires_at.strftime('%H:%M:%S UTC')}")
    print(f"    signature      : {ado.signature[:16]}…")
    print(f"    exec_context.target: {ado.exec_context.intent_binding.target}")

    assert evaluator.verify_binding(ado, proposal),   "verify_binding failed"
    print(f"  ✓ verify_binding: OK")

    evaluator.register_executed(ado, "test-agent/v1")
    print(f"  ✓ register_executed: nonce consumed")

    assert not evaluator.verify_binding(ado, proposal), "replay should be blocked"
    print(f"  ✓ replay blocked:  verify_binding after execution = False")

    print(f"\n  ✓ End-to-end check passed.")
    return True


def cmd_tests():
    header("Test Suite")
    base = _ROOT
    suites = [
        # Unit tests
        ("Evaluator v0.3 (happy path, denials, DenialContext, no requested_dsal)",
         "tests/unit/test_evaluator.py"),
        ("Crypto + DIS integrity (signatures, state machine)",
         "tests/unit/test_crypto_integrity.py"),
        # Security tests
        ("Signature coverage (19 field mutations)",
         "tests/security/test_signature_coverage.py"),
        ("Security fixes (proposal_hash / replay / delegation)",
         "tests/security/test_security_fixes.py"),
        ("ADO v5 schema (naming, max_children, ExecContext)",
         "tests/security/test_ado_v5_schema.py"),
        ("D-SAL calculator (context-driven modifiers)",
         "tests/security/test_dsal_calculator.py"),
        ("Risk pipeline (4-component evaluation)",
         "tests/security/test_risk_pipeline.py"),
        ("OSS clarity (DenialContext propagation)",
         "tests/security/test_oss_clarity.py"),
        ("Policy as Code (capability_matrix, env_rules, authority roles)",
         "tests/security/test_policy_as_code.py"),
        # Chrome extension adapter
        ("Chrome Adapter (browser_action, HITL, token lifecycle)",
         "tests/unit/test_chrome_adapter.py"),
    ]
    all_ok = True
    for label, rel in suites:
        print(f"\n▶  {label}")
        if not run_file(os.path.join(base, rel)):
            all_ok = False
    print()
    print("  ✓ All suites passed." if all_ok else "  ✗ Some suites failed.")
    return all_ok


def cmd_demo(auto=True):
    header("HITL Demo — Security Response Agent")
    print("  Mode: auto-approve\n" if auto else "  Mode: interactive\n")
    if auto:
        os.environ["SHANI_HITL_AUTO"] = "approve"
    import importlib.util
    import pathlib as _pl
    _s = importlib.util.spec_from_file_location(
        "hitl_scenario",
        str(_pl.Path(_ROOT) / "examples/hitl_approval/scenario.py"),
    )
    _m = importlib.util.module_from_spec(_s)
    _s.loader.exec_module(_m)
    _m.run()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"

    if cmd == "check":
        cmd_check()
    elif cmd == "tests":
        sys.exit(0 if cmd_tests() else 1)
    elif cmd == "demo":
        cmd_demo(auto=True)
    elif cmd == "signature":
        run_file(os.path.join(_ROOT, "tests/security/test_signature_coverage.py"))
    else:
        ok = cmd_check()
        if ok:
            print()
            cmd_tests()
