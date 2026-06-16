"""
Shani State Machine — D-SAL and DIS definitions.

D-SAL (Decision System Autonomy Level): 0–4
DIS   (Decision Integrity State): VALID / DEGRADED / VIOLATED

State transitions are deterministic and must be auditable.
No ML, no heuristics. Logic only.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable


class DSAL(IntEnum):
    """
    Decision System Autonomy Level.

    Defines the ceiling of autonomous authority an agent may hold.
    Higher = more autonomy = more governance overhead required.

    0: Proposal only — human executes
    1: Bounded automation — SOC Analyst level
    2: Supervised automation — SecOps Lead level
    3: Policy-governed automation — Org Policy level
    4: Full autonomy — Board-Level authorization required
    """

    PROPOSAL_ONLY = 0
    BOUNDED = 1
    SUPERVISED = 2
    POLICY_GOVERNED = 3
    FULL_AUTONOMY = 4

    @property
    def requires_human_authority(self) -> bool:
        return self >= DSAL.SUPERVISED

    @property
    def allows_delegation(self) -> bool:
        return self >= DSAL.SUPERVISED


class DIS(str, Enum):
    """
    Decision Integrity State.

    Represents the current health of the decision governance system.
    Shani's behavior changes based on DIS. Agents must not bypass DIS checks.

    VALID:    All assumptions hold. Normal operation.
    DEGRADED: One or more assumptions have drifted. Heightened scrutiny.
    VIOLATED: Integrity breach detected. Decision freeze in effect.
    """

    VALID = "VALID"
    DEGRADED = "DEGRADED"
    VIOLATED = "VIOLATED"

    @property
    def allows_execution(self) -> bool:
        return self == DIS.VALID

    @property
    def requires_human_review(self) -> bool:
        return self in (DIS.DEGRADED, DIS.VIOLATED)


@dataclass
class DISTransition:
    """Records a DIS state transition for audit purposes."""

    from_state: DIS
    to_state: DIS
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    triggered_by: str = "shani-core"


class DISStateMachine:
    """
    The DIS State Machine governs Shani's integrity posture.

    Transitions are explicit and logged. Regression to VALID from VIOLATED
    requires explicit reset with documented justification.
    """

    # Legal transitions: (from, to)
    _ALLOWED_TRANSITIONS: frozenset[tuple[DIS, DIS]] = frozenset(
        {
            (DIS.VALID, DIS.DEGRADED),
            (DIS.VALID, DIS.VIOLATED),
            (DIS.DEGRADED, DIS.VALID),
            (DIS.DEGRADED, DIS.VIOLATED),
            # VIOLATED → VALID intentionally requires explicit reset
        }
    )

    def __init__(self, initial: DIS = DIS.VALID, log_file: str | None = None) -> None:
        self._state: DIS = initial
        self._history: list[DISTransition] = []
        self._on_violated: list[Callable[[], None]] = []
        self._log_file: str | None = log_file

    @property
    def state(self) -> DIS:
        return self._state

    @property
    def history(self) -> list[DISTransition]:
        return list(self._history)

    def on_violated(self, callback: Callable[[], None]) -> None:
        """Register a callback invoked when DIS transitions to VIOLATED."""
        self._on_violated.append(callback)

    def transition(self, to: DIS, reason: str, triggered_by: str = "shani-core") -> DISTransition:
        """
        Attempt a state transition.

        Raises ValueError for illegal transitions.
        VIOLATED → VALID must use reset_to_valid() explicitly.
        """
        if self._state == DIS.VIOLATED and to == DIS.VALID:
            raise ValueError(
                "Cannot transition from VIOLATED to VALID via transition(). "
                "Use reset_to_valid() with documented justification."
            )

        if (self._state, to) not in self._ALLOWED_TRANSITIONS and self._state != to:
            raise ValueError(f"Illegal DIS transition: {self._state} → {to}")

        record = DISTransition(
            from_state=self._state,
            to_state=to,
            reason=reason,
            triggered_by=triggered_by,
        )
        self._history.append(record)
        self._state = to
        self._persist_transition(record)

        if to == DIS.VIOLATED:
            for cb in self._on_violated:
                cb()

        return record

    def reset_to_valid(self, justification: str, authorized_by: str) -> DISTransition:
        """
        Reset DIS from VIOLATED to VALID.

        May only be called when current state is VIOLATED (SPEC §4.4).
        Requires explicit justification and named human authority.
        This is an exceptional operation and must be audited.
        """
        if self._state != DIS.VIOLATED:
            raise ValueError(
                f"reset_to_valid() may only be called from VIOLATED state. "
                f"Current state is {self._state.value}. "
                "Use transition() for non-VIOLATED states (e.g. DEGRADED → VALID)."
            )
        if not justification.strip():
            raise ValueError("Justification must not be empty.")
        if not authorized_by.strip():
            raise ValueError("authorized_by must name a human authority.")

        record = DISTransition(
            from_state=self._state,
            to_state=DIS.VALID,
            reason=f"MANUAL RESET — {justification}",
            triggered_by=authorized_by,
        )
        self._history.append(record)
        self._state = DIS.VALID
        self._persist_transition(record)
        return record

    def _persist_transition(self, record: DISTransition) -> None:
        """Persist a DIS transition to the log file (SPEC §4.4: transitions MUST be logged)."""
        import json as _json
        import logging as _logging

        entry = {
            "timestamp": record.timestamp.isoformat(),
            "from_state": record.from_state.value,
            "to_state": record.to_state.value,
            "reason": record.reason,
            "triggered_by": record.triggered_by,
        }
        # Always emit to Python logging for audit trail (SPEC §4.4)
        _logging.getLogger("shani.dis.audit").info("DIS transition: %s", _json.dumps(entry))
        if self._log_file is None:
            return
        try:
            with open(self._log_file, "a") as f:
                f.write(_json.dumps(entry) + "\n")
        except OSError:
            pass  # log write failures must never block state transitions
