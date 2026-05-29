"""
Shani DIS Integrity Monitor.

The previous design had DIS as a state machine with no defined inputs.
That was the critical gap: DIS = assumption drift detection, but nothing
specified *what* triggers a transition.

This module defines the complete input taxonomy for DIS transitions.

DIS monitors five classes of integrity signals:

    1. Assumption Drift        — declared assumptions are no longer true
    2. Agent Identity Drift    — the proposing agent is not what it claims
    3. Environment Change      — the world changed after authorization
    4. Delegation Violation    — authority chain was broken or exceeded
    5. Replay Attack           — a previously used ADO is being replayed

Each signal class has a defined severity → DIS transition mapping.
External systems emit IntegritySignals. Shani processes them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ..schemas.state import DIS, DISStateMachine


# ---------------------------------------------------------------------------
# Signal taxonomy
# ---------------------------------------------------------------------------


class IntegritySignalType(str, Enum):
    """
    The five classes of integrity signals that can affect DIS.

    These are the only valid inputs to DIS state transitions.
    External monitors must map their observations to one of these types.
    """

    # 1. An assumption declared in a DecisionProposal is no longer true.
    #    Example: agent declared "service is in maintenance mode" but it is live.
    ASSUMPTION_DRIFT = "assumption_drift"

    # 2. The agent submitting proposals is not who it claims to be.
    #    Example: agent_id mismatch, unexpected version, or compromised identity.
    AGENT_IDENTITY_DRIFT = "agent_identity_drift"

    # 3. The environment changed after an ADO was issued, invalidating its constraints.
    #    Example: blast radius of an already-authorized action grew after authorization.
    ENVIRONMENT_CHANGE = "environment_change"

    # 4. An agent attempted to use authority it was not granted.
    #    Example: D-SAL 1 agent attempted delegation, or sub-agent exceeded parent scope.
    DELEGATION_VIOLATION = "delegation_violation"

    # 5. An ADO with a previously-used decision_id was submitted for execution.
    #    Example: replay of an expired or already-executed ADO.
    REPLAY_ATTACK = "replay_attack"


class SignalSeverity(str, Enum):
    """
    Severity determines the DIS transition triggered by a signal.

    LOW       → log only, no DIS transition
    MEDIUM    → VALID → DEGRADED (if not already)
    HIGH      → VALID/DEGRADED → VIOLATED
    CRITICAL  → VIOLATED immediately, regardless of current state
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Default severity mapping for each signal type.
# Deployments may override individual mappings in their authority config.
DEFAULT_SEVERITY_MAP: dict[IntegritySignalType, SignalSeverity] = {
    IntegritySignalType.ASSUMPTION_DRIFT:     SignalSeverity.MEDIUM,
    IntegritySignalType.AGENT_IDENTITY_DRIFT: SignalSeverity.HIGH,
    IntegritySignalType.ENVIRONMENT_CHANGE:   SignalSeverity.MEDIUM,
    IntegritySignalType.DELEGATION_VIOLATION: SignalSeverity.HIGH,
    IntegritySignalType.REPLAY_ATTACK:        SignalSeverity.CRITICAL,
}


# ---------------------------------------------------------------------------
# Signal and Event types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntegritySignal:
    """
    An integrity signal emitted by an external monitor or internal check.

    Signals are the only valid mechanism for triggering DIS transitions.
    Agents must not directly manipulate DIS.
    """
    signal_type: IntegritySignalType
    source: str             # Identifier of the monitor or component emitting this signal
    decision_id: str | None # Related ADO or proposal, if applicable
    detail: str             # Human-readable description of what was observed
    evidence: dict[str, Any] = field(default_factory=dict)  # Structured evidence
    emitted_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass(frozen=True)
class IntegrityEvent:
    """
    The result of processing an IntegritySignal.
    Records what happened: was a DIS transition triggered, and why.
    """
    signal: IntegritySignal
    severity: SignalSeverity
    dis_before: DIS
    dis_after: DIS
    action_taken: str
    processed_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


# ---------------------------------------------------------------------------
# Integrity Monitor
# ---------------------------------------------------------------------------


class DISIntegrityMonitor:
    """
    The DIS Integrity Monitor receives IntegritySignals and drives DIS transitions.

    This is the bridge between external observation and Shani's integrity state.

    Architecture:
        External Monitor → IntegritySignal → DISIntegrityMonitor → DISStateMachine

    Agents do not call this directly.
    External monitors (audit pipelines, identity verifiers, environment watchers) do.
    """

    def __init__(
        self,
        dis_machine: DISStateMachine,
        severity_map: dict[IntegritySignalType, SignalSeverity] | None = None,
    ) -> None:
        self._dis = dis_machine
        self._severity_map = severity_map or DEFAULT_SEVERITY_MAP.copy()
        self._event_log: list[IntegrityEvent] = []
        self._seen_decision_ids: set[str] = set()  # Replay attack detection

    @property
    def event_log(self) -> list[IntegrityEvent]:
        return list(self._event_log)

    def process(self, signal: IntegritySignal) -> IntegrityEvent:
        """
        Process an integrity signal and apply DIS transition if warranted.

        This is the single entry point for all integrity inputs.
        """
        severity = self._severity_map.get(signal.signal_type, SignalSeverity.MEDIUM)
        dis_before = self._dis.state
        action = "no_transition"

        # Replay attack: pre-check before severity routing
        if signal.signal_type == IntegritySignalType.REPLAY_ATTACK:
            if signal.decision_id and signal.decision_id in self._seen_decision_ids:
                severity = SignalSeverity.CRITICAL

        if severity == SignalSeverity.LOW:
            action = "logged_only"

        elif severity == SignalSeverity.MEDIUM:
            if self._dis.state == DIS.VALID:
                self._dis.transition(
                    to=DIS.DEGRADED,
                    reason=f"[{signal.signal_type.value}] {signal.detail}",
                    triggered_by=signal.source,
                )
                action = "valid→degraded"

        elif severity in (SignalSeverity.HIGH, SignalSeverity.CRITICAL):
            if self._dis.state != DIS.VIOLATED:
                self._dis.transition(
                    to=DIS.VIOLATED,
                    reason=f"[{signal.signal_type.value}] {signal.detail}",
                    triggered_by=signal.source,
                )
            action = "→violated"

        event = IntegrityEvent(
            signal=signal,
            severity=severity,
            dis_before=dis_before,
            dis_after=self._dis.state,
            action_taken=action,
        )
        self._event_log.append(event)
        return event

    def register_executed(self, decision_id: str) -> None:
        """
        Register a decision_id as executed.
        Subsequent use of the same ID will trigger a REPLAY_ATTACK signal.
        """
        self._seen_decision_ids.add(decision_id)

    def check_replay(self, decision_id: str) -> IntegritySignal | None:
        """
        Check if a decision_id has already been executed.
        Returns an IntegritySignal if replay is detected, None otherwise.
        """
        if decision_id in self._seen_decision_ids:
            return IntegritySignal(
                signal_type=IntegritySignalType.REPLAY_ATTACK,
                source="shani-boundary",
                decision_id=decision_id,
                detail=f"ADO {decision_id} has already been executed. Replay blocked.",
            )
        return None
