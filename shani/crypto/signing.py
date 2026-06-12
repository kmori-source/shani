"""
Shani Cryptographic Layer — ADO Signing Chain.

HMAC was the v0 placeholder. This replaces it.

Why HMAC was insufficient:
  - HMAC assumes a single trust boundary (one shared secret, one verifier)
  - In agent chains (A → B → C), each hop must be independently verifiable
  - HMAC cannot prove *who* signed — only that *someone with the key* signed

Why Ed25519 + chain signatures:
  - Each principal (authority, shani boundary, agent) holds an asymmetric keypair
  - Each ADO carries an ordered chain of signatures
  - Any verifier with the public keys can verify the entire chain independently
  - Replay attacks are detectable via decision_id + timestamp
  - Delegation chains are cryptographically traceable

Signature chain structure:

    authority_signature   — the policy/human authority endorses the D-SAL level
    boundary_signature    — Shani's boundary certifies the evaluation was performed
    agent_signature       — the proposing agent binds its identity to the proposal
    [delegate_signature]  — optional: sub-agent signature for delegation chains

"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Keypair abstraction (works with or without cryptography package)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigningKeypair:
    """
    An Ed25519 keypair used by a principal (authority, boundary, or agent).

    In production, private keys must be stored in a secrets manager.
    Never serialize a private key to a Decision Object or log.
    """
    principal_id: str
    private_key_bytes: bytes  # 32-byte raw Ed25519 private key seed
    public_key_bytes: bytes   # 32-byte raw Ed25519 public key

    @classmethod
    def generate(cls, principal_id: str) -> "SigningKeypair":
        """Generate a new Ed25519 keypair for a principal."""
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "cryptography package required for key generation. "
                "Install with: pip install cryptography"
            )
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(
            principal_id=principal_id,
            private_key_bytes=private_bytes,
            public_key_bytes=public_bytes,
        )

    @classmethod
    def from_seed(cls, principal_id: str, seed: bytes) -> "SigningKeypair":
        """Reconstruct keypair from a 32-byte seed (for deterministic test keys)."""
        if not _CRYPTO_AVAILABLE:
            # Fallback: use seed as both keys for offline testing
            return cls(principal_id=principal_id, private_key_bytes=seed, public_key_bytes=seed)
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(principal_id=principal_id, private_key_bytes=seed, public_key_bytes=public_bytes)


# ---------------------------------------------------------------------------
# Signature and Chain types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ADOSignature:
    """
    A single signature in the ADO signature chain.

    Each signature covers:
      - The canonical payload (decision_id + authorized_dsal + authority + expires_at)
      - All previous signatures in the chain (chained binding)
      - The signer's principal_id and timestamp
    """
    principal_id: str
    role: str              # "authority" | "boundary" | "agent" | "delegate"
    signature_b64: str     # base64-encoded Ed25519 signature (64 bytes)
    signed_at: str         # ISO 8601 UTC timestamp
    public_key_b64: str    # base64-encoded public key (32 bytes) for offline verification


@dataclass
class ADOSignatureChain:
    """
    The ordered chain of signatures on an ADO.

    Verification must proceed in order: authority → boundary → agent.
    Any gap or reordering invalidates the chain.
    """
    signatures: list[ADOSignature] = field(default_factory=list)

    def append(self, sig: ADOSignature) -> None:
        self.signatures.append(sig)

    def as_dict(self) -> dict[str, Any]:
        return {
            "signatures": [
                {
                    "principal_id": s.principal_id,
                    "role": s.role,
                    "signature_b64": s.signature_b64,
                    "signed_at": s.signed_at,
                    "public_key_b64": s.public_key_b64,
                }
                for s in self.signatures
            ]
        }

    def binding_hash(self) -> str:
        """
        Canonical hash of the entire chain.
        This is what agents store and verify as the ADO binding_hash.
        """
        chain_json = json.dumps(self.as_dict(), sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(chain_json.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Signer
# ---------------------------------------------------------------------------


class ADOSigner:
    """
    Signs ADO payloads and builds the signature chain.

    Usage:
        authority_signer = ADOSigner(authority_keypair)
        boundary_signer = ADOSigner(boundary_keypair)
        agent_signer = ADOSigner(agent_keypair)

        chain = ADOSignatureChain()
        authority_signer.sign(payload, chain, role="authority")
        boundary_signer.sign(payload, chain, role="boundary")
        agent_signer.sign(payload, chain, role="agent")

        ado.binding_hash = chain.binding_hash()
    """

    def __init__(self, keypair: SigningKeypair) -> None:
        self._keypair = keypair

    def sign(self, payload: dict[str, Any], chain: ADOSignatureChain, role: str) -> ADOSignature:
        """
        Sign the canonical payload + current chain state.

        Each signature covers:
          1. The canonical ADO payload
          2. All prior signatures in the chain (chained commitment)
        """
        canonical = self._canonical_bytes(payload, chain)
        signature_bytes = self._sign_raw(canonical)

        sig = ADOSignature(
            principal_id=self._keypair.principal_id,
            role=role,
            signature_b64=base64.b64encode(signature_bytes).decode(),
            signed_at=datetime.now(tz=timezone.utc).isoformat(),
            public_key_b64=base64.b64encode(self._keypair.public_key_bytes).decode(),
        )
        chain.append(sig)
        return sig

    @staticmethod
    def _canonical_bytes(payload: dict[str, Any], chain: ADOSignatureChain) -> bytes:
        """
        Produce the exact bytes that are signed.

        bytes = SHA256-preimage of:
            canonical_json({
                "payload":     <signature_payload from ShaniEvaluator._canonical_payload>,
                "prior_chain": <all prior signatures in chain>
            })

        The `payload` argument MUST be the full signature payload:
            canonical_json(ADO minus signature)
        covering: decision_id, proposal_hash, authority, authorized_dsal,
                  delegation_rules (all 4 fields), nonce,
                  issued_at, expires_at, exec_context (full).

        If any field is missing from payload, the signature fails to cover
        it, and an attacker can rewrite that field without detection.
        """
        combined = {
            "payload":     payload,
            "prior_chain": chain.as_dict(),
        }
        return json.dumps(combined, sort_keys=True, separators=(',', ':')).encode()

    def _sign_raw(self, data: bytes) -> bytes:
        if _CRYPTO_AVAILABLE:
            private_key = Ed25519PrivateKey.from_private_bytes(self._keypair.private_key_bytes)
            return private_key.sign(data)
        else:
            # Offline fallback: HMAC-SHA256 (for testing without cryptography package)
            import hmac as _hmac
            import hashlib as _hashlib
            return _hmac.new(self._keypair.private_key_bytes, data, _hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class ADOChainVerifier:
    """
    Verifies the full ADO signature chain.

    Requires only public keys — can be run by any party that receives an ADO.
    Does not require Shani to be running.

    This is the offline verifiability guarantee.
    """

    @staticmethod
    def verify(
        payload: dict[str, Any],
        chain: ADOSignatureChain,
        expected_roles: list[str] | None = None,
    ) -> tuple[bool, str]:
        """
        Verify the chain.

        Returns:
            (True, "OK") on success
            (False, reason) on failure
        """
        if not chain.signatures:
            return False, "Empty signature chain"

        if expected_roles is not None:
            actual_roles = [s.role for s in chain.signatures]
            if actual_roles != expected_roles:
                return False, (
                    f"Chain role mismatch. Expected: {expected_roles}, got: {actual_roles}"
                )

        # Reconstruct and verify each signature
        verified_chain = ADOSignatureChain()
        for i, sig in enumerate(chain.signatures):
            canonical = ADOSigner._canonical_bytes(payload, verified_chain)

            try:
                sig_bytes = base64.b64decode(sig.signature_b64)
                pub_bytes = base64.b64decode(sig.public_key_b64)
                ADOChainVerifier._verify_raw(pub_bytes, canonical, sig_bytes)
            except Exception as e:
                return False, f"Signature {i} ({sig.role} by {sig.principal_id}) failed: {e}"

            # Re-append to reconstruct chain state at each step
            verified_chain.append(sig)

        return True, "OK"

    @staticmethod
    def _verify_raw(public_key_bytes: bytes, data: bytes, signature: bytes) -> None:
        """Raises if verification fails."""
        if _CRYPTO_AVAILABLE:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, data)  # raises InvalidSignature on failure
        else:
            # Offline fallback: HMAC verify
            import hmac as _hmac
            import hashlib as _hashlib
            expected = _hmac.new(public_key_bytes, data, _hashlib.sha256).digest()
            if not _hmac.compare_digest(expected, signature):
                raise ValueError("HMAC verification failed (offline mode)")
