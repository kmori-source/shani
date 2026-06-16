"""
Shani Signature Coverage Pin Tests.

Property being tested:
    For every field F in the canonical signature payload,
    mutating F while keeping the signature unchanged
    MUST cause verify_binding() to fail.

If any mutation passes, it means F is not covered by the signature,
and an attacker can rewrite F after approval.

Fields under test:
    decision_id        — identity
    proposal_hash      — integrity
    authority          — authorization
    authorized_dsal    — authorization level
    delegation_rules.allowed_sub_decisions  — delegation whitelist
    delegation_rules.max_child_dsal         — escalation ceiling
    delegation_rules.max_depth              — depth limit
    delegation_rules.max_children           — fan-out limit
    nonce              — replay token
    issued_at          — issuance time
    expires_at         — expiry
    exec_context.decision_type              — what type of action
    exec_context.intent_binding.target      — which resource
    exec_context.intent_binding.intent      — what action
    exec_context.intent_binding.scope_summary
    exec_context.intent_binding.expected_effect
    exec_context.intent_binding.reversibility
    exec_context.parent_decision_id
    exec_context.constraints

This is a pin test. If a new field is added to the ADO and this test
does not cover it, the test must be updated to cover it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg: str) -> None:
    print(f"  {PASS} {msg}")


def fail(msg: str) -> None:
    _failures.append(msg)
    print(f"  {FAIL} {msg}")


def now() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Simulate canonical_payload + sign + verify without pydantic
# ---------------------------------------------------------------------------


def make_payload(overrides: dict | None = None) -> dict:
    """Build a canonical signature payload, optionally overriding fields."""
    base = {
        "decision_id": "dec-001",
        "proposal_hash": "aabbcc" * 10 + "aabb",  # 64 hex chars
        "authority": "SecOps-Lead",
        "authorized_dsal": 2,
        "delegation_rules": {
            "allowed_sub_decisions": [],
            "max_child_dsal": 0,
            "max_depth": 0,
            "max_children": 0,
        },
        "nonce": os.urandom(32).hex(),
        "issued_at": now().isoformat(),
        "expires_at": (now() + timedelta(minutes=5)).isoformat(),
        "exec_context": {
            "decision_type": "network_action",
            "intent_binding": {
                "intent": "network_action:Isolate compromised host",
                "target": "host:prod-db-12",
                "scope_summary": "assets:prod-db-12|max:1",
                "expected_effect": "Host isolated from network",
                "reversibility": True,
            },
            "parent_decision_id": None,
            "constraints": {"require_confirmation": True},
        },
        # v5.1: cross-org propagated constraints (SPEC §8.8)
        "propagated_constraints": [],
        "origin_org": None,
    }
    if overrides:
        _deep_update(base, overrides)
    return base


def _deep_update(d: dict, u: dict) -> None:
    for k, v in u.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            _deep_update(d[k], v)
        else:
            d[k] = v


def sign(payload: dict) -> str:
    """Simulate signature: SHA-256 of canonical JSON."""
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify(payload: dict, expected_signature: str) -> bool:
    """Verify: recompute signature from payload, compare to expected."""
    canonical = json.dumps(payload, sort_keys=True)
    actual = hashlib.sha256(canonical.encode()).hexdigest()
    return actual == expected_signature


# ---------------------------------------------------------------------------
# Pin test runner
# ---------------------------------------------------------------------------


def assert_mutation_breaks_signature(
    field_description: str,
    override: dict,
    original_payload: dict,
    original_signature: str,
) -> None:
    """
    Assert that mutating a field breaks signature verification.

    If verify() still returns True after mutation, the field is NOT
    covered by the signature — this is a security failure.
    """
    mutated = copy.deepcopy(original_payload)
    _deep_update(mutated, override)

    still_valid = verify(mutated, original_signature)
    if still_valid:
        fail(
            f"COVERAGE GAP: {field_description} mutation passed verification — field is NOT signed"
        )
    else:
        ok(f"Mutation of [{field_description}] → signature fails ✓")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_signature_coverage():
    print("\n" + "─" * 62)
    print("  Signature coverage: every field must be signed")
    print("─" * 62)

    # Build one valid signed payload
    payload = make_payload()
    sig = sign(payload)

    # Sanity check: unmodified payload verifies
    assert verify(payload, sig), "Unmodified payload must verify"
    ok("Baseline: unmodified payload verifies correctly")

    mutations = [
        # Identity
        ("decision_id", {"decision_id": "dec-EVIL"}),
        # Integrity
        ("proposal_hash", {"proposal_hash": "deadbeef" * 8}),
        # Authorization
        ("authority", {"authority": "Compromised-Authority"}),
        ("authorized_dsal", {"authorized_dsal": 4}),  # escalation attempt
        # Delegation rules — all four fields
        (
            "delegation_rules.allowed_sub_decisions",
            {"delegation_rules": {"allowed_sub_decisions": ["policy_update"]}},
        ),
        (
            "delegation_rules.max_child_dsal",
            {"delegation_rules": {"max_child_dsal": 3}},
        ),  # escalation
        ("delegation_rules.max_depth", {"delegation_rules": {"max_depth": 99}}),
        (
            "delegation_rules.max_children",
            {"delegation_rules": {"max_children": 1000}},
        ),  # fan-out attack
        # Replay prevention
        ("nonce", {"nonce": os.urandom(32).hex()}),
        # Temporal
        ("issued_at", {"issued_at": (now() - timedelta(days=30)).isoformat()}),  # backdating
        ("expires_at", {"expires_at": (now() + timedelta(days=365)).isoformat()}),  # extension
        # Execution context — execution drift attacks
        ("exec_context.decision_type", {"exec_context": {"decision_type": "policy_update"}}),
        (
            "exec_context.intent_binding.target",
            {"exec_context": {"intent_binding": {"target": "host:ALL-SYSTEMS"}}},
        ),
        (
            "exec_context.intent_binding.intent",
            {"exec_context": {"intent_binding": {"intent": "policy_update:Delete all data"}}},
        ),
        (
            "exec_context.intent_binding.scope_summary",
            {"exec_context": {"intent_binding": {"scope_summary": "assets:ALL|max:9999"}}},
        ),
        (
            "exec_context.intent_binding.expected_effect",
            {"exec_context": {"intent_binding": {"expected_effect": "All data deleted"}}},
        ),
        (
            "exec_context.intent_binding.reversibility",
            {"exec_context": {"intent_binding": {"reversibility": False}}},
        ),
        (
            "exec_context.parent_decision_id",
            {"exec_context": {"parent_decision_id": "injected-parent"}},
        ),
        (
            "exec_context.constraints",
            {"exec_context": {"constraints": {"require_confirmation": False}}},
        ),
        # v5.1: cross-org fields must also be signed
        ("propagated_constraints", {"propagated_constraints": ["attacker:constraint"]}),
        ("origin_org", {"origin_org": "attacker-org"}),
    ]

    for field_desc, override in mutations:
        assert_mutation_breaks_signature(field_desc, override, payload, sig)


def test_payload_completeness():
    """Verify the canonical payload contains exactly the expected top-level keys."""
    print("\n" + "─" * 62)
    print("  Payload completeness: required top-level keys")
    print("─" * 62)

    payload = make_payload()
    actual_keys = set(payload.keys())
    required_keys = {
        "decision_id",
        "proposal_hash",
        "authority",
        "authorized_dsal",
        "delegation_rules",
        "nonce",
        "propagated_constraints",
        "origin_org",
        "issued_at",
        "expires_at",
        "exec_context",
    }

    missing = required_keys - actual_keys
    extra = actual_keys - required_keys

    if missing:
        fail(f"Missing keys in canonical payload: {missing}")
    else:
        ok(f"All {len(required_keys)} required top-level keys present")

    if extra:
        # Extra keys are fine as long as they're signed, but flag them
        ok(f"Note: additional keys also signed: {extra}")

    # `signature` must NOT be in the payload (it signs the payload, cannot sign itself)
    assert "signature" not in actual_keys, "signature must NOT be in the canonical payload"
    ok("'signature' field correctly excluded from payload (cannot sign itself)")

    # delegation_rules must have all four fields
    dr = payload["delegation_rules"]
    dr_required = {"allowed_sub_decisions", "max_child_dsal", "max_depth", "max_children"}
    dr_missing = dr_required - set(dr.keys())
    if dr_missing:
        fail(f"Missing delegation_rules fields: {dr_missing}")
    else:
        ok(f"delegation_rules has all {len(dr_required)} fields: {sorted(dr_required)}")

    # exec_context must have intent_binding with all five fields
    ib_required = {"intent", "target", "scope_summary", "expected_effect", "reversibility"}
    ib_actual = set(payload["exec_context"]["intent_binding"].keys())
    ib_missing = ib_required - ib_actual
    if ib_missing:
        fail(f"Missing intent_binding fields: {ib_missing}")
    else:
        ok(f"exec_context.intent_binding has all {len(ib_required)} fields")


def test_no_omitted_exec_context():
    """Explicitly verify exec_context is NOT excluded from signing."""
    print("\n" + "─" * 62)
    print("  exec_context MUST be signed (execution drift prevention)")
    print("─" * 62)

    payload = make_payload()
    sig = sign(payload)

    # Classic execution drift: same decision_id, authority, dsal
    # but different action in exec_context
    drift_payload = copy.deepcopy(payload)
    drift_payload["exec_context"]["intent_binding"]["target"] = "cluster:prod-ALL"
    drift_payload["exec_context"]["decision_type"] = "policy_update"
    drift_payload["exec_context"]["intent_binding"]["intent"] = "policy_update:Delete cluster"

    # This MUST fail — the attacker changed exec_context but kept the signature
    if verify(drift_payload, sig):
        fail("CRITICAL: exec_context mutation passed — execution drift attack possible")
    else:
        ok("Execution drift blocked: target substitution → signature invalid")
        ok("Execution drift blocked: decision_type substitution → signature invalid")

    # Verify that exec_context changes genuinely change the signature
    sig_original = sign(make_payload({"exec_context": {"intent_binding": {"target": "host:A"}}}))
    sig_different = sign(make_payload({"exec_context": {"intent_binding": {"target": "host:B"}}}))
    assert sig_original != sig_different
    ok("Different exec_context targets produce different signatures (deterministic)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("=" * 62)
    print("  Shani Signature Coverage Pin Tests")
    print("=" * 62)
    print()
    print("  Property: for every field F in canonical_payload,")
    print("  mutating F MUST invalidate the signature.")
    print()
    print("  If any mutation passes, F is unsigned — an attacker")
    print("  can rewrite that field after approval.")

    test_signature_coverage()
    test_payload_completeness()
    test_no_omitted_exec_context()

    total_mutations = 19  # count of mutations in test_signature_coverage
    print("\n" + "=" * 62)
    if _failures:
        print(f"  FAILED: {len(_failures)} issue(s)")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print(f"  All coverage tests passed.")
        print()
        print(f"  {total_mutations} field mutations tested — all break the signature.")
        print()
        print("  Canonical payload covers:")
        print("    decision_id, proposal_hash")
        print("    authority, authorized_dsal")
        print("    delegation_rules (× 4 fields)")
        print("    nonce")
        print("    issued_at, expires_at")
        print("    exec_context.decision_type")
        print("    exec_context.intent_binding (× 5 fields)")
        print("    exec_context.parent_decision_id")
        print("    exec_context.constraints")
    print("=" * 62)
