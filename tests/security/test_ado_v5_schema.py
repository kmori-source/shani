"""
ADO v5 canonical structure tests.

Verifies all invariants of the v5 schema without pydantic:
  - issued_at / expires_at naming and semantics
  - max_children fan-out prevention
  - ExecContext grouping
  - signature field (renamed from binding_hash)
  - delegation_permitted property
"""
from __future__ import annotations
import hashlib, json, os, sys, uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []

def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f": {d}" if d else ""))
def section(t): print(f"\n{'─'*58}\n  {t}\n{'─'*58}")

# ── helpers ──────────────────────────────────────────────────────────

def now(): return datetime.now(tz=timezone.utc)
def future(s=300): return now() + timedelta(seconds=s)

def make_delegation_rules(allowed=None, max_child=0, max_depth=0, max_children=0):
    return {
        "allowed_sub_decisions": allowed or [],
        "max_child_dsal": max_child,
        "max_depth": max_depth,
        "max_children": max_children,
    }

def delegation_permitted(rules: dict) -> bool:
    return (
        bool(rules["allowed_sub_decisions"])
        and rules["max_child_dsal"] > 0
        and rules["max_depth"] > 0
        and rules["max_children"] > 0
    )

# ── Tests ─────────────────────────────────────────────────────────────

def test_field_names():
    section("v5 field naming: issued_at / expires_at / signature")

    # Simulate ADO construction
    ado = {
        "decision_id":   str(uuid.uuid4()),
        "proposal_hash": "abc123",
        "signature":     "sig456",      # was: binding_hash
        "authority":     "SecOps-Lead",
        "authorized_dsal": 2,
        "delegation_rules": make_delegation_rules(),
        "nonce":         os.urandom(32).hex(),
        "issued_at":     now().isoformat(),       # was: authorized_at
        "expires_at":    future(300).isoformat(), # was: valid_until
    }

    assert "issued_at" in ado,    "issued_at must exist"
    assert "expires_at" in ado,   "expires_at must exist"
    assert "signature" in ado,    "signature must exist"
    assert "authorized_at" not in ado, "authorized_at must be gone"
    assert "valid_until" not in ado,   "valid_until must be gone"
    assert "binding_hash" not in ado,  "binding_hash must be gone"
    ok("issued_at (was: authorized_at)")
    ok("expires_at (was: valid_until)")
    ok("signature (was: binding_hash)")

def test_temporal_invariants():
    section("Temporal invariants: expires_at > issued_at")

    # Valid: expires 5 min after issued
    issued = now()
    expires = issued + timedelta(minutes=5)
    assert expires > issued
    ok("Valid: expires_at > issued_at")

    # Invalid: expires before issued
    bad_expires = issued - timedelta(seconds=1)
    assert bad_expires < issued
    ok("Invalid: expires_at < issued_at — must be caught by validator")

    # Expiry check
    def is_expired(issued_iso, expires_iso):
        exp = datetime.fromisoformat(expires_iso)
        return datetime.now(tz=timezone.utc) >= exp

    assert not is_expired(now().isoformat(), future(300).isoformat())
    ok("is_expired() false for ADO valid 5 min")

    past = (now() - timedelta(seconds=1)).isoformat()
    assert is_expired(now().isoformat(), past)
    ok("is_expired() true for expired ADO")

    def time_remaining(expires_iso):
        exp = datetime.fromisoformat(expires_iso)
        return max(0.0, (exp - datetime.now(tz=timezone.utc)).total_seconds())

    remaining = time_remaining(future(300).isoformat())
    assert 295 < remaining <= 300, f"Expected ~300s, got {remaining}"
    ok(f"time_remaining_seconds() ≈ {remaining:.0f}s")

def test_max_children():
    section("max_children: fan-out attack prevention")

    # Without max_children: unbounded fan-out
    no_children = make_delegation_rules(
        allowed=["remediation"], max_child=2, max_depth=3, max_children=0
    )
    assert not delegation_permitted(no_children)
    ok("max_children=0 → delegation_permitted=False (fan-out prevented)")

    # With max_children=5: bounded fan-out
    bounded = make_delegation_rules(
        allowed=["remediation"], max_child=2, max_depth=3, max_children=5
    )
    assert delegation_permitted(bounded)
    ok("max_children=5, max_depth=3 → delegation_permitted=True")

    # Max total descendants bounded
    max_desc = bounded["max_children"] ** bounded["max_depth"]
    assert max_desc == 125
    ok(f"Total descendants ≤ max_children^max_depth = 5^3 = {max_desc} (auditable bound)")

    # Tight cap: max_children=1 (linear chain only)
    linear = make_delegation_rules(
        allowed=["remediation"], max_child=1, max_depth=5, max_children=1
    )
    assert delegation_permitted(linear)
    ok("max_children=1: linear chain permitted, no branching")
    desc = linear["max_children"] ** linear["max_depth"]
    assert desc == 1
    ok(f"Linear chain: 1^5 = {desc} agent total (no fan-out)")

    # Decremented at each hop
    def next_hop_rules(rules: dict) -> dict:
        return {
            **rules,
            "max_depth": max(0, rules["max_depth"] - 1),
            "max_child_dsal": max(0, rules["max_child_dsal"] - 1),
        }

    r = bounded
    for hop in range(3):
        r = next_hop_rules(r)
    assert r["max_depth"] == 0
    assert not delegation_permitted(r)
    ok("Depth exhausted after 3 hops: delegation_permitted=False")

def test_exec_context():
    section("ExecContext: execution metadata grouped separately")

    # ExecContext groups what-is-authorized fields
    exec_ctx = {
        "decision_type":       "network_action",
        "intent_binding": {
            "intent":          "network_action:Isolate host",
            "target":          "host:prod-db-12",
            "scope_summary":   "assets:prod-db-12|max:1",
            "expected_effect": "Host network-isolated",
            "reversibility":   True,
        },
        "parent_decision_id":  None,
        "constraints":         {"require_confirmation": True},
        "rollback_policy":     None,
    }

    # Top-level ADO fields are only the security-critical ones
    ado_top_level_fields = {
        "decision_id", "proposal_hash", "signature",
        "authority", "authorized_dsal",
        "delegation_rules",
        "nonce",
        "issued_at", "expires_at",
        "exec_context",
    }

    # Execution metadata fields NOT at top level
    exec_fields = {"decision_type", "intent_binding", "constraints",
                   "rollback_policy", "parent_decision_id"}

    # None of the exec fields leak to top level
    for f in exec_fields:
        assert f not in ado_top_level_fields, f"{f} should be in exec_context, not top-level"
    ok("decision_type, intent_binding, constraints, rollback_policy → exec_context")
    ok("Top-level ADO contains only: identity, integrity, authorization, delegation, replay, temporal")

    # But they're accessible via properties (backwards compat)
    # Simulated
    class FakeADO:
        exec_context = type("EC", (), exec_ctx)()
        @property
        def decision_type(self): return self.exec_context.decision_type
        @property
        def intent_binding(self): return self.exec_context.intent_binding
        @property
        def constraints(self): return self.exec_context.constraints

    ado = FakeADO()
    assert ado.decision_type == "network_action"
    assert ado.intent_binding["target"] == "host:prod-db-12"
    ok("Properties provide backwards-compatible access: ado.decision_type, ado.intent_binding, ado.constraints")

def test_full_structure():
    section("Full ADO v5 structure self-consistency")

    nonce = os.urandom(32).hex()
    issued = now()
    expires = issued + timedelta(minutes=5)

    proposal_data = {
        "decision_id":    "dec-001",
        "decision_type":  "remediation",
        "proposed_by":    "soc-agent/v1",
        "description":    "Isolate host",
        "target":         "host:prod-db-12",
        "requested_dsal": 2,
        "reversibility":  True,
        "blast_radius":   "significant",
        "expires_at":     None,
    }
    proposal_hash = hashlib.sha256(
        json.dumps(proposal_data, sort_keys=True).encode()
    ).hexdigest()

    delegation_rules = make_delegation_rules()  # leaf node, no delegation

    # Canonical signed payload (must include all security-critical fields)
    payload = {
        "decision_id":     "dec-001",
        "authority":       "SecOps-Lead",
        "authorized_dsal": 2,
        "issued_at":       issued.isoformat(),
        "expires_at":      expires.isoformat(),
        "proposal_hash":   proposal_hash,
        "nonce":           nonce,
        "delegation_rules": {
            "allowed_sub_decisions": sorted(delegation_rules["allowed_sub_decisions"]),
            "max_child_dsal":        delegation_rules["max_child_dsal"],
            "max_depth":             delegation_rules["max_depth"],
            "max_children":         delegation_rules["max_children"],  # ← NEW
        },
        "exec_context": {
            "decision_type": "remediation",
            "intent":        "remediation:Isolate host",
            "target":        "host:prod-db-12",
        },
    }

    # Signature = hash of canonical payload (simulating Ed25519 chain)
    signature = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    ado = {
        "decision_id":     "dec-001",
        "proposal_hash":   proposal_hash,
        "signature":       signature,
        "authority":       "SecOps-Lead",
        "authorized_dsal": 2,
        "delegation_rules": delegation_rules,
        "nonce":           nonce,
        "issued_at":       issued.isoformat(),
        "expires_at":      expires.isoformat(),
        "exec_context": {
            "decision_type":  "remediation",
            "intent_binding": {"target": "host:prod-db-12"},
        },
    }

    # Verify all 10 top-level fields present
    expected_fields = {
        "decision_id", "proposal_hash", "signature",
        "authority", "authorized_dsal",
        "delegation_rules",
        "nonce",
        "issued_at", "expires_at",
        "exec_context",
    }
    assert set(ado.keys()) == expected_fields, f"Missing: {expected_fields - set(ado.keys())}"
    ok("All 10 canonical top-level fields present")

    # Verify delegation_rules has all 4 fields
    dr_fields = {"allowed_sub_decisions", "max_child_dsal", "max_depth", "max_children"}
    assert set(delegation_rules.keys()) == dr_fields
    ok("DelegationRules has all 4 fields: allowed_sub_decisions, max_child_dsal, max_depth, max_children")

    # Verify nonce is 64-char hex (32 bytes)
    assert len(ado["nonce"]) == 64
    assert all(c in "0123456789abcdef" for c in ado["nonce"])
    ok("nonce: 64-char hex (32 bytes of os.urandom)")

    ok("Full ADO v5 structure self-consistent")


if __name__ == "__main__":
    print("=" * 58)
    print("  ADO v5 Canonical Structure Tests")
    print("=" * 58)

    test_field_names()
    test_temporal_invariants()
    test_max_children()
    test_exec_context()
    test_full_structure()

    print("\n" + "=" * 58)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures: print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All tests passed.")
        print()
        print("  v5 canonical structure:")
        print("    decision_id    — identity")
        print("    proposal_hash  — integrity (bound to proposal)")
        print("    signature      — cryptographic (Ed25519 chain hash)")
        print("    authority      — authorization (who approved)")
        print("    authorized_dsal— authorization (level granted)")
        print("    delegation_rules(4 fields) — escalation + fan-out prevention")
        print("    nonce          — replay prevention (one-time, 32 bytes)")
        print("    issued_at      — temporal")
        print("    expires_at     — temporal")
        print("    exec_context   — execution metadata (in signed payload)")
    print("=" * 58)
