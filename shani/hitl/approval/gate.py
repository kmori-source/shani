"""
Shani HITL Gate.

The HITLGate wraps a ShaniEvaluator and inserts human approval
at configurable D-SAL thresholds.

    evaluator = ShaniEvaluator(...)
    gate = HITLGate(
        evaluator=evaluator,
        approval_required_at_dsal=2,   # require human for D-SAL >= 2
        channel=CLIApprovalChannel(),  # or Slack, webhook, etc.
    )

    # Drop-in replacement for evaluator.evaluate()
    result = gate.evaluate(proposal)   # blocks until human decides (or times out)

The agent code does not change.
Only the infrastructure wiring changes.

For async / non-blocking use:
    request_id = gate.submit(proposal)    # returns immediately
    # ... human decides out-of-band ...
    result = gate.collect(request_id)     # polls or blocks
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from ...core.evaluator import DeniedDecision, EvaluationResult, ShaniEvaluator
from ...schemas.decision import DecisionProposal, AuthorizedDecisionObject
from ...integrity.monitor import IntegritySignal, IntegritySignalType
from .request import ApprovalRequest, ApprovalStatus, InterventionPoint

logger = logging.getLogger("shani.hitl")


# ---------------------------------------------------------------------------
# Channel protocol — the only thing you implement to add a new interface
# ---------------------------------------------------------------------------


@runtime_checkable
class ApprovalChannel(Protocol):
    """
    The single interface to implement for any human notification channel.

    Implementations:
        CLIApprovalChannel    — blocks on stdin (included)
        WebhookApprovalChannel — POST to URL, poll for response (included)
        CallbackApprovalChannel — async callback pattern (included)
        SlackApprovalChannel   — (example stub, included)

    Implement this protocol to add Slack, PagerDuty, email, custom UI, etc.
    without touching any other Shani code.
    """

    def send(self, request: ApprovalRequest) -> None:
        """Notify the human that an approval is waiting."""
        ...

    def poll(self, request_id: str) -> ApprovalRequest | None:
        """
        Check if the human has decided.
        Returns the updated request or None if still pending.
        """
        ...


# ---------------------------------------------------------------------------
# HITL Gate
# ---------------------------------------------------------------------------


class HITLGate:
    """
    Human-in-the-Loop Gate.

    Wraps a ShaniEvaluator and adds human approval at configured D-SAL thresholds.

    Approval flow:
        1. Proposal arrives
        2. If dsal >= approval_required_at_dsal → create ApprovalRequest → send to channel
        3. Block (or return pending) until human decides or timeout
        4. If approved → pass to ShaniEvaluator → return ADO
        5. If denied/timeout → return DeniedDecision + emit DIS signal

    The evaluator's own D-SAL and policy checks still run after approval.
    Human approval is necessary but not sufficient.
    """

    def __init__(
        self,
        evaluator: ShaniEvaluator,
        channel: ApprovalChannel,
        approval_required_at_dsal: int = 2,
        timeout_minutes: int = 15,
        poll_interval_seconds: float = 1.0,
        timeout_is_deny: bool = True,
    ) -> None:
        self._evaluator = evaluator
        self._channel = channel
        self._threshold = approval_required_at_dsal
        self._timeout_minutes = timeout_minutes
        self._poll_interval = poll_interval_seconds
        self._timeout_is_deny = timeout_is_deny
        self._pending: dict[str, ApprovalRequest] = {}  # request_id → request

    @property
    def dis(self):
        return self._evaluator.dis

    def evaluate(self, proposal: DecisionProposal) -> EvaluationResult:
        """
        Synchronous evaluate — blocks until human decides (or times out).
        Drop-in replacement for ShaniEvaluator.evaluate().
        """
        # D-SAL is computed from policy, not from code
        _base_dsal = self._get_base_dsal(proposal)
        if _base_dsal < self._threshold:
            logger.debug("HITL bypass | dsal=%d < threshold=%d", _base_dsal, self._threshold)
            return self._evaluator.evaluate(proposal)

        # Above threshold: require human approval first
        req = self._build_request(proposal)
        self._pending[req.request_id] = req

        logger.info(
            "HITL required | decision=%s dsal=%d authority=%s timeout=%s",
            req.decision_id[:8],
            req.effective_dsal if hasattr(req, "effective_dsal") else "?",
            req.required_authority,
            req.timeout_at.strftime("%H:%M UTC"),
        )
        self._channel.send(req)

        # Block until decided or timeout
        return self._wait_for_decision(req, proposal)

    def submit(self, proposal: DecisionProposal) -> str:
        """
        Async submit — returns request_id immediately.
        Use collect(request_id) to retrieve result after human decides.
        """
        _base_dsal = self._get_base_dsal(proposal)
        if _base_dsal < self._threshold:
            raise ValueError(
                f"submit() called for dsal={_base_dsal} below threshold {self._threshold}. "
                "Use evaluate() for synchronous non-approval path."
            )
        req = self._build_request(proposal)
        self._pending[req.request_id] = req
        self._channel.send(req)
        logger.info(
            "HITL submitted | request=%s decision=%s", req.request_id[:8], req.decision_id[:8]
        )
        return req.request_id

    def collect(self, request_id: str, proposal: DecisionProposal) -> EvaluationResult:
        """
        Retrieve result for a previously submitted request.
        Raises if request is still pending.
        """
        req = self._pending.get(request_id)
        if req is None:
            raise KeyError(f"No pending request: {request_id}")

        # Refresh from channel
        updated = self._channel.poll(request_id)
        if updated:
            self._pending[request_id] = updated
            req = updated

        if req.is_expired():
            req.expire()

        if req.status == ApprovalStatus.PENDING:
            raise RuntimeError(f"Request {request_id[:8]} is still pending.")

        return self._resolve(req, proposal)

    def get_pending(self) -> list[ApprovalRequest]:
        """Returns all currently pending approval requests."""
        for req in list(self._pending.values()):
            if req.is_expired():
                req.expire()
        return [r for r in self._pending.values() if r.status == ApprovalStatus.PENDING]

    def register_executed(self, ado_or_id, agent_id: str = "") -> None:
        """Accept either an ADO object or a decision_id string."""
        self._evaluator.register_executed(ado_or_id, agent_id)

    def verify_binding(self, ado, proposal=None) -> bool:
        return self._evaluator.verify_binding(ado, proposal)

    def activate_kill_switch(self) -> None:
        self._evaluator.activate_kill_switch()

    def deactivate_kill_switch(self, justification: str, authorized_by: str) -> None:
        self._evaluator.deactivate_kill_switch(justification, authorized_by)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _wait_for_decision(
        self,
        req: ApprovalRequest,
        proposal: DecisionProposal,
    ) -> EvaluationResult:
        while True:
            if req.is_expired():
                req.expire()
                break

            updated = self._channel.poll(req.request_id)
            if updated:
                self._pending[req.request_id] = updated
                req = updated

            if req.status != ApprovalStatus.PENDING:
                break

            time.sleep(self._poll_interval)

        return self._resolve(req, proposal)

    def _resolve(
        self,
        req: ApprovalRequest,
        proposal: DecisionProposal,
    ) -> EvaluationResult:
        del self._pending[req.request_id]

        if req.status == ApprovalStatus.APPROVED:
            logger.info(
                "HITL APPROVED | by=%s decision=%s note=%s",
                req.decided_by,
                req.decision_id[:8],
                req.decision_note,
            )
            return self._evaluator.evaluate(proposal)

        elif req.status == ApprovalStatus.DENIED:
            logger.warning(
                "HITL DENIED | by=%s decision=%s reason=%s",
                req.decided_by,
                req.decision_id[:8],
                req.decision_note,
            )
            return DeniedDecision(
                decision_id=proposal.decision_id,
                reason=f"Human denied: {req.decision_note or '(no reason given)'} (by {req.decided_by})",
                proposal=proposal,
            )

        else:  # TIMEOUT or REVOKED
            logger.warning("HITL TIMEOUT | decision=%s", req.decision_id[:8])
            self._evaluator.process_integrity_signal(
                IntegritySignal(
                    signal_type=IntegritySignalType.ASSUMPTION_DRIFT,
                    source="shani-hitl",
                    decision_id=proposal.decision_id,
                    detail=f"HITL approval timed out for {proposal.decision_type.value} on {proposal.target}",
                )
            )
            return DeniedDecision(
                decision_id=proposal.decision_id,
                reason=f"HITL approval timed out after {self._timeout_minutes} minutes.",
                proposal=proposal,
            )

    def _get_effective_dsal(self, proposal: DecisionProposal) -> int:
        """
        runs RiskPipeline to obtain the effective D-SAL。
        used for the HITL trigger decision。context-aware value, not bare base_dsal。
        """
        try:
            ev = self._evaluator
            if hasattr(ev, "_policy") and hasattr(ev, "_risk_pipeline"):
                base = ev._policy.required_dsal(proposal.decision_type)
                pr = ev._risk_pipeline.evaluate(proposal, base)
                return pr.effective_dsal
            elif hasattr(ev, "_evaluator"):
                inner = ev._evaluator
                if hasattr(inner, "_policy") and hasattr(inner, "_risk_pipeline"):
                    base = inner._policy.required_dsal(proposal.decision_type)
                    pr = inner._risk_pipeline.evaluate(proposal, base)
                    return pr.effective_dsal
        except Exception:
            pass
        # Fallback: base_dsal from policy
        if hasattr(self._evaluator, "_policy"):
            return self._evaluator._policy.required_dsal(proposal.decision_type)
        return 1

    def _get_base_dsal(self, proposal: DecisionProposal) -> int:
        """Legacy: base D-SAL from policy only (without context modifiers)."""
        return self._get_effective_dsal(proposal)

    def _build_request(self, proposal: DecisionProposal) -> ApprovalRequest:
        from datetime import timedelta

        # determines the authority role using the context-aware effective D-SAL
        effective_dsal = self._get_effective_dsal(proposal)

        authority_label = "unknown"
        if hasattr(self._evaluator, "_authority"):
            authority_label = self._evaluator._authority.resolve_authority(effective_dsal)
        elif hasattr(self._evaluator, "_evaluator") and hasattr(
            self._evaluator._evaluator, "_authority"
        ):
            authority_label = self._evaluator._evaluator._authority.resolve_authority(
                effective_dsal
            )

        return ApprovalRequest(
            decision_id=proposal.decision_id,
            decision_type=proposal.decision_type.value,
            proposed_by=proposal.proposed_by,
            target=proposal.target,
            intent=f"{proposal.decision_type.value}: {proposal.description}",
            blast_radius=proposal.blast_radius.value,
            reversibility=proposal.reversibility,
            evidence_summary=[f"[{e.source}] {e.content}" for e in proposal.evidence],
            assumptions=list(proposal.assumptions),
            confidence=proposal.confidence,
            parent_decision_id=proposal.parent_decision_id,
            required_authority=authority_label,
            timeout_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )
