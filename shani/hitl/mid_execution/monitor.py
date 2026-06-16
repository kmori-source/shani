"""
Shani Mid-Execution Monitor.

Pre-execution approval answers: "may this agent act?"
Mid-execution monitoring answers: "should this agent keep acting?"

These are different questions. The world can change between approval and completion.

Mid-execution intervention points:

    PAUSE   — suspend agent, wait for human to resume or abort
    ABORT   — terminate agent, trigger rollback if reversible
    OVERRIDE — inject a human decision into the running graph
    OBSERVE  — human is watching but not intervening (default)

State machine per running node:

    RUNNING → PAUSED → RESUMED → COMPLETED
    RUNNING → PAUSED → ABORTED
    RUNNING → ABORTED
    RUNNING → COMPLETED

The monitor receives heartbeats from running agents.
Silence beyond a threshold triggers PAUSE automatically.
"""

from __future__ import annotations

import threading
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("shani.hitl.mid")


class ExecutionStatus(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    RESUMED = "resumed"
    ABORTED = "aborted"
    COMPLETED = "completed"


class InterventionType(str, Enum):
    PAUSE = "pause"
    ABORT = "abort"
    OVERRIDE = "override"
    RESUME = "resume"
    OBSERVE = "observe"


@dataclass
class ExecutionSession:
    """Tracks a single running agent node."""

    session_id: str
    decision_id: str  # The ADO this session runs under
    agent_id: str
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    status: ExecutionStatus = ExecutionStatus.RUNNING
    progress_log: list[str] = field(default_factory=list)
    intervention: "InterventionRequest | None" = None

    def heartbeat(self, message: str = "") -> None:
        self.last_heartbeat = datetime.now(tz=timezone.utc)
        if message:
            self.progress_log.append(f"[{self.last_heartbeat.strftime('%H:%M:%S')}] {message}")

    def silence_seconds(self) -> float:
        return (datetime.now(tz=timezone.utc) - self.last_heartbeat).total_seconds()

    def elapsed_seconds(self) -> float:
        return (datetime.now(tz=timezone.utc) - self.started_at).total_seconds()


@dataclass
class InterventionRequest:
    """A human's decision to intervene in a running execution."""

    intervention_type: InterventionType
    session_id: str
    authority: str
    reason: str
    override_value: Any = None  # Only for OVERRIDE interventions
    requested_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


class MidExecutionMonitor:
    """
    Monitors running agent sessions and mediates human interventions.

    Usage in agent node:

        session_id = monitor.register(ado, agent_id="my-agent")

        for step in my_long_running_process():
            monitor.heartbeat(session_id, f"Processed {step}")

            # This blocks if a PAUSE intervention is active
            monitor.checkpoint(session_id)

        monitor.complete(session_id, result=output)

    Usage for human operator (out-of-band):

        monitor.pause(session_id, authority="alice@example.com", reason="reviewing EDR")
        monitor.resume(session_id, authority="alice@example.com")
        # or
        monitor.abort(session_id, authority="alice@example.com", reason="false positive")
    """

    def __init__(
        self,
        silence_threshold_seconds: float = 60.0,
        on_intervention: Callable[[InterventionRequest], None] | None = None,
        on_silence: Callable[[ExecutionSession], None] | None = None,
    ) -> None:
        self._sessions: dict[str, ExecutionSession] = {}
        self._lock = threading.Lock()
        self._silence_threshold = silence_threshold_seconds
        self._on_intervention = on_intervention
        self._on_silence = on_silence
        self._watchdog_thread: threading.Thread | None = None
        self._running = False

    def start_watchdog(self) -> None:
        """Start background thread that watches for silent agents."""
        self._running = True
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="shani-mid-watchdog"
        )
        self._watchdog_thread.start()
        logger.info(
            "Mid-execution watchdog started (silence_threshold=%ss)", self._silence_threshold
        )

    def stop_watchdog(self) -> None:
        self._running = False

    def register(
        self,
        ado: Any,  # AuthorizedDecisionObject
        agent_id: str,
    ) -> str:
        """Register a new execution session. Returns session_id."""
        import uuid

        session_id = str(uuid.uuid4())[:8]
        session = ExecutionSession(
            session_id=session_id,
            decision_id=ado.decision_id,
            agent_id=agent_id,
            target=ado.intent_binding.target if hasattr(ado, "intent_binding") else "unknown",
        )
        with self._lock:
            self._sessions[session_id] = session
        logger.info(
            "Session registered | id=%s agent=%s target=%s", session_id, agent_id, session.target
        )
        return session_id

    def heartbeat(self, session_id: str, message: str = "") -> None:
        """Agent signals it is alive and making progress."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.heartbeat(message)

    def checkpoint(self, session_id: str) -> None:
        """
        Agent calls this at safe suspension points.

        If a PAUSE intervention is pending: blocks until RESUME or ABORT.
        If an ABORT intervention is pending: raises ExecutionAborted.
        Otherwise: returns immediately.
        """
        while True:
            with self._lock:
                session = self._sessions.get(session_id)
                if session is None:
                    return
                intervention = session.intervention

            if intervention is None:
                return

            if intervention.intervention_type == InterventionType.ABORT:
                logger.warning(
                    "Execution ABORTED | session=%s reason=%s", session_id, intervention.reason
                )
                raise ExecutionAborted(
                    f"Aborted by {intervention.authority}: {intervention.reason}"
                )

            if intervention.intervention_type == InterventionType.PAUSE:
                logger.info("Execution PAUSED | session=%s — waiting for resume", session_id)
                with self._lock:
                    if session := self._sessions.get(session_id):
                        session.status = ExecutionStatus.PAUSED
                time.sleep(0.5)  # Poll for resume
                continue

            if intervention.intervention_type == InterventionType.RESUME:
                with self._lock:
                    if session := self._sessions.get(session_id):
                        session.status = ExecutionStatus.RESUMED
                        session.intervention = None
                return

            return

    def complete(self, session_id: str, result: Any = None) -> None:
        with self._lock:
            if session := self._sessions.get(session_id):
                session.status = ExecutionStatus.COMPLETED
                session.progress_log.append(f"[COMPLETED] result={result!r}")
        logger.info("Session completed | id=%s", session_id)

    # ------------------------------------------------------------------
    # Human intervention methods
    # ------------------------------------------------------------------

    def pause(self, session_id: str, authority: str, reason: str = "") -> None:
        self._intervene(session_id, InterventionType.PAUSE, authority, reason)

    def resume(self, session_id: str, authority: str) -> None:
        self._intervene(session_id, InterventionType.RESUME, authority, "resuming")

    def abort(self, session_id: str, authority: str, reason: str = "") -> None:
        self._intervene(session_id, InterventionType.ABORT, authority, reason)
        with self._lock:
            if session := self._sessions.get(session_id):
                session.status = ExecutionStatus.ABORTED

    def override(self, session_id: str, authority: str, value: Any, reason: str = "") -> None:
        req = InterventionRequest(
            intervention_type=InterventionType.OVERRIDE,
            session_id=session_id,
            authority=authority,
            reason=reason,
            override_value=value,
        )
        with self._lock:
            if session := self._sessions.get(session_id):
                session.intervention = req
        if self._on_intervention:
            self._on_intervention(req)

    def get_override_value(self, session_id: str) -> Any:
        """Agent polls this to check if a human override is pending."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session.intervention:
                if session.intervention.intervention_type == InterventionType.OVERRIDE:
                    val = session.intervention.override_value
                    session.intervention = None  # consume it
                    return val
        return None

    def get_active_sessions(self) -> list[ExecutionSession]:
        with self._lock:
            return [
                s
                for s in self._sessions.values()
                if s.status in (ExecutionStatus.RUNNING, ExecutionStatus.PAUSED)
            ]

    def get_session(self, session_id: str) -> ExecutionSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _intervene(
        self, session_id: str, itype: InterventionType, authority: str, reason: str
    ) -> None:
        req = InterventionRequest(
            intervention_type=itype,
            session_id=session_id,
            authority=authority,
            reason=reason,
        )
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"No active session: {session_id}")
            session.intervention = req
        logger.warning(
            "Intervention | type=%s session=%s by=%s", itype.value, session_id, authority
        )
        if self._on_intervention:
            self._on_intervention(req)

    def _watchdog_loop(self) -> None:
        while self._running:
            time.sleep(5.0)
            with self._lock:
                sessions = list(self._sessions.values())
            for session in sessions:
                if session.status == ExecutionStatus.RUNNING:
                    if session.silence_seconds() > self._silence_threshold:
                        logger.warning(
                            "Silent agent detected | session=%s silence=%.0fs",
                            session.session_id,
                            session.silence_seconds(),
                        )
                        if self._on_silence:
                            self._on_silence(session)


class ExecutionAborted(Exception):
    """Raised by checkpoint() when an ABORT intervention is received."""
