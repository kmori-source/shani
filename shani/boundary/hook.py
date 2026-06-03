"""
Shani Decision Boundary and Decision Firewall.

DecisionBoundary: single-agent boundary (backward compatible)
DecisionFirewall: governs entire agent chains

Architecture:

    Agent A
      ↓
    Firewall.enter("agent-a", proposal_a)        → ADO_a
      ↓
    Agent B  (spawned by A, references ADO_a)
      ↓
    Firewall.enter("agent-b", proposal_b, parent_ado=ADO_a)  → ADO_b
      ↓
    API / External System

No agent in the chain may act without its own ADO.
No agent may exceed its parent's scope.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from ..core.evaluator import DeniedDecision, EvaluationResult, ShaniEvaluator
from ..schemas.decision import AuthorizedDecisionObject, DecisionProposal
from ..schemas.posture import PostureRefinementRequest

# Callable that receives a PostureRefinementRequest and notifies the principal
# via a separate channel (not HITL) — SPEC §8.5.
# Implementations may send email, Slack, push notification, etc.
PrincipalNotificationChannel = Callable[[PostureRefinementRequest], None]

logger = logging.getLogger("shani.boundary")
F = TypeVar("F", bound=Callable[..., Any])


class DenialContext:
    """
    Complete context explaining why a decision was denied.

    This object is attached to exceptions raised by the Hook.
    HITL notifications, audit logs, and Slack alerts
    use this context to explain the denial to humans.

    "justification" philosophy:
        Shani always provides denial reasons in a form humans can understand.
        A denial without a reason becomes a black box that humans cannot override.
    """

    def __init__(
        self,
        reason: str,
        decision_id: str | None = None,
        pipeline_result=None,       # PipelineResult (risk_score, rules, evidence, framing)
        proposal=None,              # snapshot of the DecisionProposal
        rule_name: str | None = None,
        risk_score: float | None = None,
        evidence_quality: float | None = None,
        framing_risk: float | None = None,
    ):
        self.reason           = reason
        self.decision_id      = decision_id
        self.pipeline_result  = pipeline_result
        self.proposal         = proposal
        self.rule_name        = rule_name
        self.risk_score       = risk_score
        self.evidence_quality = evidence_quality
        self.framing_risk     = framing_risk

    def to_human_summary(self) -> dict:
        """
        Human-readable denial summary.
        HITL channels (Slack, Web UI, CLI) use this for display.
        """
        summary: dict = {
            "reason": self.reason,
            "decision_id": self.decision_id[:8] if self.decision_id else None,
        }
        if self.rule_name:
            summary["rule_triggered"] = self.rule_name
        if self.risk_score is not None:
            summary["risk_score"] = round(self.risk_score, 3)
        if self.evidence_quality is not None:
            summary["evidence_quality"] = round(self.evidence_quality, 3)
        if self.framing_risk is not None and self.framing_risk > 0.1:
            summary["framing_risk"] = round(self.framing_risk, 3)
        if self.pipeline_result is not None:
            pr = self.pipeline_result
            summary["risk_dimensions"] = {
                d.name: round(d.score, 3)
                for d in pr.risk_score.dimensions
            }
            if pr.rule_result.applied_rules:
                summary["rules_applied"] = pr.rule_result.applied_rules
            if pr.evidence_eval.flags:
                summary["evidence_flags"] = pr.evidence_eval.flags
        if self.proposal is not None:
            summary["proposal_snapshot"] = {
                "decision_type": self.proposal.decision_type.value,
                "target":        self.proposal.target,
                "blast_radius":  self.proposal.blast_radius.value,
                "reversibility": self.proposal.reversibility,
                "evidence_count": len(self.proposal.evidence),
                "confidence":    self.proposal.confidence,
            }
        return summary

    def __str__(self) -> str:
        return self.reason


class DecisionBoundaryViolation(Exception):
    """
    Raised when an agent attempts execution without a valid ADO,
    or when chain integrity is violated.

    A DenialContext is attached to this exception.
    HITL and audit logs use it to explain the denial to humans.
    Do not catch this exception silently.
    """

    def __init__(self, message: str, context: DenialContext | None = None):
        super().__init__(message)
        self.context = context or DenialContext(reason=message)

    def to_human_summary(self) -> dict:
        return self.context.to_human_summary()


@dataclass
class DecisionChainNode:
    agent_id: str
    ado: AuthorizedDecisionObject
    parent_node: "DecisionChainNode | None" = None
    entered_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    exited_at: datetime | None = None
    execution_result: Any = None

    @property
    def depth(self) -> int:
        if self.parent_node is None:
            return 0
        return self.parent_node.depth + 1

    def lineage(self) -> list["DecisionChainNode"]:
        if self.parent_node is None:
            return [self]
        return self.parent_node.lineage() + [self]


class DecisionFirewall:
    """
    Governs an entire agent chain.
    Each agent must earn its own ADO — no inherited authority.
    """

    def __init__(
        self,
        evaluator: ShaniEvaluator,
        max_chain_depth: int = 5,
        principal_notifier: PrincipalNotificationChannel | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._max_depth = max_chain_depth
        self._active_nodes: dict[str, DecisionChainNode] = {}
        self._completed: list[DecisionChainNode] = []
        self._principal_notifier = principal_notifier

    def enter(
        self,
        agent_id: str,
        proposal: DecisionProposal,
        parent_ado: AuthorizedDecisionObject | None = None,
    ) -> AuthorizedDecisionObject:
        parent_node = None
        if parent_ado is not None:
            parent_node = self._active_nodes.get(parent_ado.decision_id)
            if parent_node is None:
                raise DecisionBoundaryViolation(
                    f"Agent '{agent_id}' claims parent ADO {parent_ado.decision_id} "
                    "but it is not in the active firewall chain."
                )
            if parent_node.depth + 1 > self._max_depth:
                raise DecisionBoundaryViolation(
                    f"Chain depth exceeds max {self._max_depth}."
                )
            # Note: D-SAL escalation check is performed inside evaluator._check_delegation_rules_eff

        result = self._evaluator.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            logger.warning("Firewall DENIED | agent=%s reason=%s", agent_id, result.reason)
            raise DecisionBoundaryViolation(f"Firewall denied '{agent_id}': {result.reason}")

        # SPEC §8.5: agent MUST halt the proposed operation on PostureRefinementRequest
        if isinstance(result, PostureRefinementRequest):
            logger.info(
                "Firewall POSTURE-AMBIGUOUS | agent=%s proposal=%s principal=%s",
                agent_id, result.proposal_id, result.principal_id,
            )
            # SPEC §8.5 behavior 2: notify principal via a separate channel (not HITL)
            if self._principal_notifier is not None:
                try:
                    self._principal_notifier(result)
                    logger.info(
                        "Principal notified | principal=%s proposal=%s",
                        result.principal_id, result.proposal_id,
                    )
                except Exception as notify_exc:
                    logger.error(
                        "Principal notifier failed | principal=%s error=%s",
                        result.principal_id, notify_exc, exc_info=True,
                    )
            else:
                logger.warning(
                    "No principal_notifier configured — SPEC §8.5 requires notifying "
                    "principal '%s' via a separate channel (not HITL). "
                    "Pass principal_notifier= to DecisionFirewall.",
                    result.principal_id,
                )
            raise DecisionBoundaryViolation(
                f"Firewall: operation halted for '{agent_id}' — PostureRefinementRequest "
                f"(principal={result.principal_id}): {result.ambiguity}"
            )

        if not self._evaluator.verify_binding(result):
            raise DecisionBoundaryViolation(f"ADO {result.decision_id} binding failed.")

        node = DecisionChainNode(agent_id=agent_id, ado=result, parent_node=parent_node)
        self._active_nodes[result.decision_id] = node
        logger.info("Firewall ENTER | agent=%s dsal=%s depth=%d", agent_id, result.authorized_dsal, node.depth)
        return result

    def exit(self, decision_id: str, result: Any = None, success: bool = True) -> DecisionChainNode:
        node = self._active_nodes.pop(decision_id, None)
        if node is None:
            raise DecisionBoundaryViolation(f"exit() called for unknown decision {decision_id}")
        node.exited_at = datetime.now(tz=timezone.utc)
        node.execution_result = result
        self._completed.append(node)
        if success:
            self._evaluator.register_executed(node.ado)
        logger.info("Firewall EXIT | agent=%s success=%s", node.agent_id, success)
        return node

    def enforce(self, fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(ado: AuthorizedDecisionObject, *args: Any, **kwargs: Any) -> Any:
            if not isinstance(ado, AuthorizedDecisionObject):
                raise DecisionBoundaryViolation(f"Requires ADO. Got {type(ado).__name__}.")
            if ado.decision_id not in self._active_nodes:
                raise DecisionBoundaryViolation(f"ADO {ado.decision_id} not in active chain.")
            if not self._evaluator.verify_binding(ado):
                raise DecisionBoundaryViolation(f"ADO {ado.decision_id} binding failed.")
            if datetime.now(tz=timezone.utc) > ado.expires_at:
                raise DecisionBoundaryViolation(f"ADO {ado.decision_id} expired.")
            return fn(ado, *args, **kwargs)
        return wrapper  # type: ignore[return-value]

    def active_chain_summary(self) -> list[dict[str, Any]]:
        return [
            {
                "agent_id": n.agent_id,
                "decision_id": n.ado.decision_id,
                "decision_type": n.ado.decision_type.value,
                "dsal": n.ado.authorized_dsal,
                "target": n.ado.intent_binding.target,
                "depth": n.depth,
                "parent_decision_id": n.parent_node.ado.decision_id if n.parent_node else None,
            }
            for n in self._active_nodes.values()
        ]

    def audit_trail(self) -> list[dict[str, Any]]:
        trail = []
        for node in self._completed:
            for hop in node.lineage():
                trail.append({
                    "decision_id": hop.ado.decision_id,
                    "agent_id": hop.agent_id,
                    "decision_type": hop.ado.decision_type.value,
                    "target": hop.ado.intent_binding.target,
                    "dsal": hop.ado.authorized_dsal,
                    "depth": hop.depth,
                    "parent_decision_id": hop.parent_node.ado.decision_id if hop.parent_node else None,
                })
        return trail


class DecisionBoundary:
    """Single-agent boundary. Backward compatible with v1/v2."""

    def __init__(
        self,
        evaluator: ShaniEvaluator,
        principal_notifier: PrincipalNotificationChannel | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._principal_notifier = principal_notifier

    def check(self, proposal: DecisionProposal) -> EvaluationResult:
        result = self._evaluator.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            logger.warning("Denied | id=%s reason=%s", result.decision_id, result.reason)
        elif isinstance(result, PostureRefinementRequest):
            # SPEC §8.5: log, notify principal, and return — caller must halt
            logger.info(
                "PostureRefinementRequest | proposal=%s principal=%s ambiguity=%s",
                result.proposal_id, result.principal_id, result.ambiguity,
            )
            # SPEC §8.5 behavior 2: notify principal via a separate channel (not HITL)
            if self._principal_notifier is not None:
                try:
                    self._principal_notifier(result)
                    logger.info(
                        "Principal notified | principal=%s proposal=%s",
                        result.principal_id, result.proposal_id,
                    )
                except Exception as notify_exc:
                    logger.error(
                        "Principal notifier failed | principal=%s error=%s",
                        result.principal_id, notify_exc, exc_info=True,
                    )
            else:
                logger.warning(
                    "No principal_notifier configured — SPEC §8.5 requires notifying "
                    "principal '%s' via a separate channel (not HITL). "
                    "Pass principal_notifier= to DecisionBoundary.",
                    result.principal_id,
                )
        else:
            logger.info("Authorized | id=%s dsal=%s", result.decision_id, result.authorized_dsal)
            self._evaluator.register_executed(result)
        return result

    def enforce(self, fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(ado: AuthorizedDecisionObject, *args: Any, **kwargs: Any) -> Any:
            if not isinstance(ado, AuthorizedDecisionObject):
                raise DecisionBoundaryViolation(f"Requires ADO. Got {type(ado).__name__}.")
            if not self._evaluator.verify_binding(ado):
                raise DecisionBoundaryViolation(f"Binding failed: {ado.decision_id}")
            if datetime.now(tz=timezone.utc) > ado.expires_at:
                raise DecisionBoundaryViolation(f"ADO expired: {ado.decision_id}")
            result = fn(ado, *args, **kwargs)
            self._evaluator.register_executed(ado)
            return result
        return wrapper  # type: ignore[return-value]
