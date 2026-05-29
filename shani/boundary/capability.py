"""
shani/boundary/capability.py

ExecutionBoundary — no ADO means no Capability means no execution.

Problem:
    Without this boundary, an agent can call external APIs directly,
    bypassing Shani entirely. An ADO alone is just a record of authorization;
    it does not physically prevent unauthorized execution.

Solution:
    All executable operations are encapsulated in Capability objects.
    A Capability can only be created via ExecutionBoundary.issue_capability(ado).
    issue_capability() returns a Capability only after full ADO verification.

    In other words:
        call_external_api(url)           <- does not exist; cannot be called directly
        cap = boundary.issue_capability(ado)
        cap.http_get(url)               <- only works with a verified ADO

Structure:

    ExecutionBoundary
      └─ issue_capability(ado, proposal?) → Capability
                                              │
                                              ├─ http_get(url)
                                              ├─ http_post(url, payload)
                                              ├─ read_file(path)
                                              ├─ write_file(path, content)
                                              └─ run_command(cmd)

    Capability enforces:
      - Operations must match the ADO's exec_context.intent_binding.target
      - ADO must not be expired
      - Single-use: once consumed, cannot be used again
      - Only operations listed in allowed_operations may be called
"""
from __future__ import annotations

import logging
import subprocess
from typing import Any

logger = logging.getLogger("shani.boundary.capability")


class CapabilityError(Exception):
    """Raised when attempting to obtain a Capability without a valid ADO."""


class CapabilityExpired(CapabilityError):
    """Raised when attempting to use a Capability after its ADO has expired."""


class CapabilityExhausted(CapabilityError):
    """Raised when attempting to use a Capability that has already been consumed."""


class OperationNotAllowed(CapabilityError):
    """Raised when calling an operation not permitted by this Capability."""


class TargetMismatch(CapabilityError):
    """Raised when the operation target does not match the ADO-approved target prefix."""


# ---------------------------------------------------------------------------
# Capability — a single-use execution right bound to one ADO
# ---------------------------------------------------------------------------


class Capability:
    """
    An execution right bound to a verified ADO.
    Can only be created via ExecutionBoundary.issue_capability().

    Design principles:
        - __init__ is private; direct Capability() construction is blocked.
        - Each method re-validates the ADO before execution.
        - If target_prefix is set, the operation target must match it.
        - Single-use: the first call sets _used=True;
          all subsequent calls raise CapabilityExhausted.
    """

    _SENTINEL = object()  # prevents direct instantiation

    def __init__(self, _sentinel, ado, allowed_operations: set[str], target_prefix: str):
        if _sentinel is not Capability._SENTINEL:
            raise CapabilityError(
                "Capability cannot be instantiated directly. "
                "Use ExecutionBoundary.issue_capability(ado) instead."
            )
        self._ado = ado
        self._allowed = allowed_operations
        self._target_prefix = target_prefix
        self._used = False          # once True, no further use is permitted
        self._lock = __import__("threading").Lock()  # thread-safe single-use guarantee

        logger.info(
            "Capability issued | decision=%s ops=%s target_prefix=%s",
            ado.decision_id[:8], sorted(allowed_operations), target_prefix[:40],
        )

    # ── internal validation ───────────────────────────────────────────────

    def _check(self, operation: str, target: str) -> None:
        """
        Called before every operation. Raises on any violation.

        Single-use guarantee:
            Uses a lock to atomically check and set _used.
            If two threads attempt to use the same Capability concurrently,
            exactly one succeeds; the other raises CapabilityExhausted.
        """
        # ── single-use check (thread-safe) ───────────────────────────────
        with self._lock:
            if self._used:
                raise CapabilityExhausted(
                    f"Capability(decision={self._ado.decision_id[:8]}) has already been used. "
                    "ADOs are one-time tokens. A new proposal is required for each operation."
                )
            # Mark as used — all subsequent calls will raise CapabilityExhausted
            self._used = True

        # ── expiry check ─────────────────────────────────────────────────
        if self._ado.is_expired():
            raise CapabilityExpired(
                f"ADO {self._ado.decision_id[:8]} has expired"
                f" (expired at: {self._ado.expires_at.strftime('%H:%M:%S UTC')})"
            )

        # ── operation allowlist check ─────────────────────────────────────
        if operation not in self._allowed:
            raise OperationNotAllowed(
                f"Operation '{operation}' is not permitted by this Capability. "
                f"Allowed operations: {sorted(self._allowed)}"
            )

        # ── target prefix check ───────────────────────────────────────────
        if self._target_prefix and not target.startswith(self._target_prefix):
            raise TargetMismatch(
                f"Target '{target}' does not match the ADO-approved target prefix "
                f"'{self._target_prefix}'. Operations outside the approved target are forbidden."
            )

    # ── executable operations ─────────────────────────────────────────────

    def http_get(self, url: str) -> dict[str, Any]:
        """HTTP GET. Available only when the ADO authorizes data_access."""
        self._check("http_get", url)
        logger.info("Capability.http_get | decision=%s url=%s", self._ado.decision_id[:8], url)
        # Production: return httpx.get(url).json()
        # Simulation:
        return {
            "url": url, "status": 200,
            "data": {"items": ["item-1", "item-2"], "latency": "38ms"},
            "via": f"Capability(decision={self._ado.decision_id[:8]})",
        }

    def http_post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """HTTP POST. Available only when the ADO authorizes configuration_change."""
        self._check("http_post", url)
        logger.info("Capability.http_post | decision=%s url=%s", self._ado.decision_id[:8], url)
        # Production: return httpx.post(url, json=payload).json()
        return {
            "url": url, "status": 201, "created": payload,
            "id": "resource-001",
            "via": f"Capability(decision={self._ado.decision_id[:8]})",
        }

    def read_file(self, path: str) -> str:
        """Read a file."""
        self._check("read_file", path)
        logger.info("Capability.read_file | decision=%s path=%s", self._ado.decision_id[:8], path)
        try:
            return open(path).read()[:500]
        except Exception as e:
            return f"[read error: {e}]"

    def write_file(self, path: str, content: str) -> str:
        """Write content to a file."""
        self._check("write_file", path)
        logger.info("Capability.write_file | decision=%s path=%s", self._ado.decision_id[:8], path)
        with open(path, "w") as f:
            f.write(content)
        return f"written: {path}"

    def run_command(self, cmd: str) -> str:
        """Execute a shell command."""
        self._check("run_command", cmd)
        logger.info("Capability.run_command | decision=%s cmd=%s", self._ado.decision_id[:8], cmd[:40])
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout or result.stderr

    def __repr__(self) -> str:
        return (
            f"Capability(decision={self._ado.decision_id[:8]}, "
            f"ops={sorted(self._allowed)}, "
            f"target_prefix={self._target_prefix!r}, "
            f"expires={self._ado.expires_at.strftime('%H:%M UTC')})"
        )


# ---------------------------------------------------------------------------
# ExecutionBoundary — the sole source of Capability objects
# ---------------------------------------------------------------------------
#
# CapabilityMatrix is managed by DecisionPolicyProvider (authority/policy.py).
# ExecutionBoundary obtains operation permissions exclusively via the policy.
# No operation mappings are hardcoded in this file.


class ExecutionBoundary:
    """
    The only place where ADOs are converted into executable Capabilities.

    Nothing can be executed without passing through here.
    If the ADO is invalid, no Capability is issued.

    The capability_matrix is received from DecisionPolicyProvider via
    dependency injection. This class holds no operation mappings of its own.
    """

    def __init__(self, gate, capability_matrix=None) -> None:
        """
        Args:
            gate: HITLGate or ShaniEvaluator
            capability_matrix: DecisionPolicyProvider.capability_matrix
                               If None, resolved automatically from gate.
        """
        self._gate = gate
        if capability_matrix is not None:
            self._capability_matrix = capability_matrix
        elif hasattr(gate, '_evaluator') and hasattr(gate._evaluator, '_policy'):
            self._capability_matrix = gate._evaluator._policy.capability_matrix
        elif hasattr(gate, '_policy'):
            self._capability_matrix = gate._policy.capability_matrix
        else:
            # Fallback: use CapabilityMatrix defaults if policy is not reachable
            from ..authority.policy import CapabilityMatrix
            self._capability_matrix = CapabilityMatrix()
            logger.warning(
                "ExecutionBoundary: could not resolve capability_matrix from gate. "
                "Using defaults. Pass capability_matrix explicitly for production use."
            )

    def issue_capability(self, ado, proposal=None) -> Capability:
        """
        Verify an ADO and issue a Capability.

        Verification steps:
          1. ADO signature is valid (not tampered)
          2. If proposal provided, proposal_hash matches
          3. Nonce has not yet been consumed (replay prevention)
          4. ADO is not expired

        Returns a Capability only if all checks pass.
        Raises CapabilityError if any check fails.
        """
        if not self._gate.verify_binding(ado, proposal):
            raise CapabilityError(
                f"ADO {ado.decision_id[:8]} verification failed. "
                "Signature invalid, proposal_hash mismatch, or possible replay attack."
            )

        if ado.is_expired():
            raise CapabilityExpired(f"ADO {ado.decision_id[:8]} has expired.")

        # Resolve allowed operations from capability_matrix (single source of truth)
        dt = ado.exec_context.decision_type.value
        allowed_ops = self._capability_matrix.get_operations(dt)
        if not allowed_ops:
            raise CapabilityError(
                f"No operations permitted for decision_type '{dt}'. "
                f"Check capability_matrix in policy.yaml. "
                f"Known types: {self._capability_matrix.known_types()}"
            )

        # Derive target prefix (for HTTP, restrict to scheme + host)
        target_prefix = ado.exec_context.intent_binding.target
        if target_prefix.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(target_prefix)
            target_prefix = f"{parsed.scheme}://{parsed.netloc}"

        # Consume the nonce — marks this ADO as executed
        self._gate.register_executed(ado, agent_id="execution-boundary")

        cap = Capability(
            Capability._SENTINEL,
            ado=ado,
            allowed_operations=allowed_ops,
            target_prefix=target_prefix,
        )
        logger.info(
            "ExecutionBoundary issued capability | decision=%s dt=%s ops=%s target=%s",
            ado.decision_id[:8], dt, sorted(allowed_ops), target_prefix[:40],
        )
        return cap
