"""
tests/security/test_evidence_signature.py

Tests for EvidenceItem signature verification (issue #89).

Property being tested:
    EvidenceItem.signature / signed_by fields are verified by EvidenceEvaluator.
    - Valid signature   → trust_multiplier boosted by _SIGNATURE_VALID_BONUS
    - Invalid signature → trust_multiplier overridden to _SIGNATURE_INVALID_MULTIPLIER
    - Missing signature → no change (backwards-compatible)
    - Only one of signature/signed_by present → treated as invalid
"""

from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import warnings

warnings.filterwarnings("ignore")

from shani.schemas.decision import EvidenceItem
from shani.risk.evidence import (
    EvidenceEvaluator,
    _canonical_evidence_bytes,
    _verify_evidence_signature,
    _SIGNATURE_INVALID_MULTIPLIER,
    _SIGNATURE_VALID_BONUS,
    _TRUST_MULTIPLIER,
    SourceTrust,
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
# Helpers
# ---------------------------------------------------------------------------


def _make_keypair():
    """Generate an Ed25519 keypair for testing."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            PrivateFormat,
            NoEncryption,
        )

        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv_bytes, pub_bytes
    except ImportError:
        # Offline mode: use a fixed 32-byte seed
        key = os.urandom(32)
        return key, key  # private == public in HMAC offline mode


def _sign_evidence(
    source: str, content: str, priv_bytes: bytes, pub_bytes: bytes
) -> tuple[str, str]:
    """Sign evidence content, return (signature_b64, pub_key_b64)."""
    data = _canonical_evidence_bytes(source, content)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig_bytes = priv.sign(data)
    except ImportError:
        import hmac as _hmac
        import hashlib as _hashlib

        sig_bytes = _hmac.new(priv_bytes, data, _hashlib.sha256).digest()
    return base64.b64encode(sig_bytes).decode(), base64.b64encode(pub_bytes).decode()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_unsigned_evidence_unchanged():
    """Evidence without signature fields behaves identically to before."""
    print("\n  ── Unsigned evidence: backwards-compatible behaviour")
    item = EvidenceItem(source="monitor", content="CPU high", confidence=0.8)
    result = _verify_evidence_signature(item)
    if result is None:
        ok("Unsigned item → verify returns None (no signature)")
    else:
        fail(f"Expected None for unsigned item, got {result!r}")

    ev = EvidenceEvaluator()
    eval_result = ev.evaluate([item])
    ie = eval_result.item_evaluations[0]
    if ie["signature_status"] == "unsigned":
        ok("signature_status == 'unsigned' in item_evaluation")
    else:
        fail(f"Expected 'unsigned', got {ie['signature_status']!r}")
    if "signature_invalid" not in eval_result.flags:
        ok("No 'signature_invalid' flag for unsigned evidence")
    else:
        fail("'signature_invalid' flag unexpectedly set for unsigned evidence")


def test_valid_signature_boosts_trust():
    """Valid external signature raises the effective trust multiplier."""
    print("\n  ── Valid signature: trust boost applied")
    priv_bytes, pub_bytes = _make_keypair()
    source = "self_report_audit"
    content = "Vulnerability confirmed by external scanner"
    sig_b64, pub_b64 = _sign_evidence(source, content, priv_bytes, pub_bytes)

    item = EvidenceItem(
        source=source,
        content=content,
        confidence=0.7,
        signature=sig_b64,
        signed_by=pub_b64,
    )

    result = _verify_evidence_signature(item)
    if result is True:
        ok("_verify_evidence_signature returns True for valid signature")
    else:
        fail(f"Expected True, got {result!r}")

    ev = EvidenceEvaluator()
    eval_result = ev.evaluate([item])
    ie = eval_result.item_evaluations[0]
    if ie["signature_status"] == "valid":
        ok("signature_status == 'valid'")
    else:
        fail(f"Expected 'valid', got {ie['signature_status']!r}")

    # trust_multiplier should be base + bonus, capped at 1.0
    from shani.risk.evidence import classify_source

    trust = classify_source(source)
    expected_mult = round(min(1.0, _TRUST_MULTIPLIER[trust] + _SIGNATURE_VALID_BONUS), 3)
    if abs(ie["trust_multiplier"] - expected_mult) < 1e-6:
        ok(
            f"trust_multiplier boosted to {ie['trust_multiplier']} (base + {_SIGNATURE_VALID_BONUS})"
        )
    else:
        fail(f"Expected trust_multiplier={expected_mult}, got {ie['trust_multiplier']}")

    if "signature_invalid" not in eval_result.flags:
        ok("No 'signature_invalid' flag for valid signature")
    else:
        fail("'signature_invalid' flag wrongly set for valid signature")


def test_invalid_signature_penalized():
    """Tampered signature is detected and trust is heavily penalized."""
    print("\n  ── Invalid signature: trust penalty applied")
    priv_bytes, pub_bytes = _make_keypair()
    source = "monitor"
    content = "Disk full"
    sig_b64, pub_b64 = _sign_evidence(source, content, priv_bytes, pub_bytes)

    # Tamper: change content after signing
    item = EvidenceItem(
        source=source,
        content="Disk NOT full (tampered)",
        confidence=0.9,
        signature=sig_b64,
        signed_by=pub_b64,
    )

    result = _verify_evidence_signature(item)
    if result is False:
        ok("_verify_evidence_signature returns False for tampered content")
    else:
        fail(f"Expected False for tampered evidence, got {result!r}")

    ev = EvidenceEvaluator()
    eval_result = ev.evaluate([item])
    ie = eval_result.item_evaluations[0]
    if ie["signature_status"] == "invalid":
        ok("signature_status == 'invalid'")
    else:
        fail(f"Expected 'invalid', got {ie['signature_status']!r}")
    if abs(ie["trust_multiplier"] - _SIGNATURE_INVALID_MULTIPLIER) < 1e-6:
        ok(f"trust_multiplier overridden to {_SIGNATURE_INVALID_MULTIPLIER}")
    else:
        fail(
            f"Expected trust_multiplier={_SIGNATURE_INVALID_MULTIPLIER}, got {ie['trust_multiplier']}"
        )
    if eval_result.flags.get("signature_invalid"):
        ok("'signature_invalid' flag set")
    else:
        fail("'signature_invalid' flag NOT set for invalid signature")


def test_partial_signature_fields_invalid():
    """signature without signed_by (or vice versa) is treated as invalid."""
    print("\n  ── Partial signature fields: treated as invalid")

    item_sig_only = EvidenceItem(
        source="edr",
        content="Alert fired",
        confidence=0.8,
        signature="ZmFrZXNpZw==",
        signed_by=None,
    )
    r1 = _verify_evidence_signature(item_sig_only)
    if r1 is False:
        ok("signature without signed_by → False (invalid)")
    else:
        fail(f"Expected False, got {r1!r}")

    item_key_only = EvidenceItem(
        source="edr",
        content="Alert fired",
        confidence=0.8,
        signature=None,
        signed_by="ZmFrZWtleQ==",
    )
    r2 = _verify_evidence_signature(item_key_only)
    if r2 is False:
        ok("signed_by without signature → False (invalid)")
    else:
        fail(f"Expected False, got {r2!r}")


def test_canonical_bytes_deterministic():
    """_canonical_evidence_bytes is deterministic and covers source + content."""
    print("\n  ── Canonical bytes: determinism and field coverage")
    b1 = _canonical_evidence_bytes("monitor", "CPU 99%")
    b2 = _canonical_evidence_bytes("monitor", "CPU 99%")
    if b1 == b2:
        ok("Identical inputs produce identical bytes")
    else:
        fail("Non-deterministic canonical bytes")

    b3 = _canonical_evidence_bytes("monitor", "CPU 50%")
    if b1 != b3:
        ok("Different content → different bytes (content coverage)")
    else:
        fail("Content change not reflected in canonical bytes")

    b4 = _canonical_evidence_bytes("edr", "CPU 99%")
    if b1 != b4:
        ok("Different source → different bytes (source coverage)")
    else:
        fail("Source change not reflected in canonical bytes")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("=" * 62)
    print("  EvidenceItem Signature Verification Tests (issue #89)")
    print("=" * 62)

    test_unsigned_evidence_unchanged()
    test_valid_signature_boosts_trust()
    test_invalid_signature_penalized()
    test_partial_signature_fields_invalid()
    test_canonical_bytes_deterministic()

    print("\n" + "=" * 62)
    if _failures:
        print(f"  FAILED: {len(_failures)} issue(s)")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All evidence signature tests passed.")
    print("=" * 62)
