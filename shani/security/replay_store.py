"""
Shani Replay Store — Global One-Time Capability Registry.

Problem with the previous design:
    register_executed() stored consumed decision_ids in-process memory.
    Process restart = replay store wiped = same ADO can be replayed.

    More critically: nonce was never in the signed payload, so an attacker
    could strip the nonce field and the signature would still verify.

This module provides:
    1. NonceStore protocol — pluggable backend interface
    2. InMemoryNonceStore  — for testing / single-process use
    3. FileNonceStore      — survives restarts (append-only log)
    4. The nonce is now part of the signed canonical payload,
       so stripping it invalidates the signature.

Replay prevention logic:
    On issue:    ADO.nonce = os.urandom(32).hex()  (in schema)
    On execute:  store.consume(ado.nonce, ado.decision_id)
                 → raises NonceAlreadyConsumed if nonce was used before
    On verify:   store.is_consumed(ado.nonce) checked BEFORE execution

Design invariant:
    A nonce, once consumed, is NEVER removed from the store.
    The store is append-only.
    There is no "un-consume" operation.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

# Cross-process file locking (Unix: fcntl.flock; Windows: no-op with documented limitation).
try:
    import fcntl as _fcntl

    def _acquire_file_lock(f: object) -> None:
        _fcntl.flock(f.fileno(), _fcntl.LOCK_EX)  # type: ignore[attr-defined]

    def _release_file_lock(f: object) -> None:
        _fcntl.flock(f.fileno(), _fcntl.LOCK_UN)  # type: ignore[attr-defined]

except ImportError:
    # Windows: fcntl is unavailable. Threading lock still prevents in-process races.
    # For production multi-process Windows deployments, use a database-backed store.
    def _acquire_file_lock(f: object) -> None:  # type: ignore[misc]
        pass

    def _release_file_lock(f: object) -> None:  # type: ignore[misc]
        pass


class NonceAlreadyConsumed(Exception):
    """
    Raised when an ADO nonce has already been registered as executed.
    This is a replay attack or a programming error. Treat it as the former.
    """


@runtime_checkable
class NonceStore(Protocol):
    """
    Protocol for replay store backends.

    Implement this to use Redis, PostgreSQL, DynamoDB, etc.
    The only requirement: consume() must be atomic.
    """

    def consume(self, nonce: str, decision_id: str, agent_id: str) -> None:
        """
        Mark nonce as consumed. Raises NonceAlreadyConsumed if already used.
        Must be atomic — no TOCTOU window.
        """
        ...

    def is_consumed(self, nonce: str) -> bool:
        """Check if nonce has been consumed. Does not modify state."""
        ...

    def get_record(self, nonce: str) -> dict | None:
        """Return consumption record or None."""
        ...


# ---------------------------------------------------------------------------
# In-memory store (testing / single-process)
# ---------------------------------------------------------------------------


class InMemoryNonceStore:
    """
    Thread-safe in-memory nonce store.

    Survives only for the lifetime of the process.
    Use FileNonceStore or a persistent backend in production.
    """

    def __init__(self) -> None:
        self._consumed: dict[str, dict] = {}
        self._lock = threading.Lock()

    def consume(self, nonce: str, decision_id: str, agent_id: str = "") -> None:
        with self._lock:
            if nonce in self._consumed:
                existing = self._consumed[nonce]
                raise NonceAlreadyConsumed(
                    f"Nonce {nonce[:16]}... was already consumed.\n"
                    f"  First use: decision={existing['decision_id'][:8]} "
                    f"agent={existing['agent_id']} at={existing['consumed_at']}\n"
                    f"  Replay attempt: decision={decision_id[:8]} agent={agent_id}\n"
                    "This is a replay attack or a programming error."
                )
            self._consumed[nonce] = {
                "decision_id": decision_id,
                "agent_id": agent_id,
                "consumed_at": datetime.now(tz=timezone.utc).isoformat(),
            }

    def is_consumed(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._consumed

    def get_record(self, nonce: str) -> dict | None:
        with self._lock:
            return self._consumed.get(nonce)

    def __len__(self) -> int:
        with self._lock:
            return len(self._consumed)


# ---------------------------------------------------------------------------
# File-backed store (survives restarts)
# ---------------------------------------------------------------------------


class FileNonceStore:
    """
    Append-only file-backed nonce store.

    Format: one JSON record per line (newline-delimited JSON).
    On startup: loads all previously consumed nonces into memory.
    On consume: appends to file, then updates memory.

    The file is append-only. Never truncate or rewrite it.
    Treat it as an audit log.

    Production note: for multi-process deployments, use a database-backed
    store with row-level locking instead.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self._path.with_suffix(".lock")
        self._memory = InMemoryNonceStore()
        self._file_lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        """Load existing records into memory on startup."""
        if not self._path.exists():
            return
        with self._path.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    nonce = record.get("nonce")
                    if nonce and nonce not in self._memory._consumed:
                        self._memory._consumed[nonce] = {
                            "decision_id": record.get("decision_id", ""),
                            "agent_id": record.get("agent_id", ""),
                            "consumed_at": record.get("consumed_at", ""),
                        }
                except json.JSONDecodeError:
                    pass  # Corrupted line — skip (log in production)

    def consume(self, nonce: str, decision_id: str, agent_id: str = "") -> None:
        # Fast path: check in-memory cache (no I/O on replay within same process)
        if self._memory.is_consumed(nonce):
            existing = self._memory.get_record(nonce)
            raise NonceAlreadyConsumed(
                f"Replay detected: nonce {nonce[:16]}... already consumed. "
                f"Original: decision={existing['decision_id'][:8]} at={existing['consumed_at']}"  # type: ignore[index]
            )

        record = {
            "nonce": nonce,
            "decision_id": decision_id,
            "agent_id": agent_id,
            "consumed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

        with self._file_lock:
            # Double-check under threading lock (in-process TOCTOU prevention)
            if self._memory.is_consumed(nonce):
                existing = self._memory.get_record(nonce)
                raise NonceAlreadyConsumed(
                    f"Replay detected (concurrent): nonce {nonce[:16]}... "
                    f"Original: {existing['decision_id'][:8]}"  # type: ignore[index]
                )

            # Acquire cross-process exclusive lock via a dedicated lock file.
            # This closes the TOCTOU window when multiple processes share the
            # same nonce store file (e.g. parallel agent workers).
            with self._lock_path.open("a") as lock_file:
                _acquire_file_lock(lock_file)
                try:
                    # Under the cross-process lock, re-scan the store file for
                    # the nonce. Another process may have written it while we
                    # were waiting to acquire the lock.
                    if self._path.exists():
                        with self._path.open("r") as rf:
                            for line in rf:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    if entry.get("nonce") == nonce:
                                        rec = {
                                            "decision_id": entry.get("decision_id", ""),
                                            "agent_id": entry.get("agent_id", ""),
                                            "consumed_at": entry.get("consumed_at", ""),
                                        }
                                        self._memory._consumed[nonce] = rec
                                        raise NonceAlreadyConsumed(
                                            f"Replay detected (cross-process): "
                                            f"nonce {nonce[:16]}... already consumed by "
                                            f"decision={rec['decision_id'][:8]}"
                                        )
                                except json.JSONDecodeError:
                                    pass

                    # Safe to write: nonce confirmed absent under exclusive lock
                    with self._path.open("a") as f:
                        f.write(json.dumps(record) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                finally:
                    _release_file_lock(lock_file)

            self._memory._consumed[nonce] = {
                "decision_id": record["decision_id"],
                "agent_id": record["agent_id"],
                "consumed_at": record["consumed_at"],
            }

    def is_consumed(self, nonce: str) -> bool:
        return self._memory.is_consumed(nonce)

    def get_record(self, nonce: str) -> dict | None:
        return self._memory.get_record(nonce)

    def record_count(self) -> int:
        return len(self._memory)
