"""
Shani HITL — Human-in-the-Loop Approval Layer.

Design principle:
    Shani does not replace human judgment.
    Shani routes decisions to the right human, at the right time,
    with the right context — and enforces that the answer is binding.

Three intervention points:

    PRE-EXECUTION   Agent proposes → Human approves/denies → ADO issued
    MID-EXECUTION   Agent is running → Human can pause/abort/override
    POST-EXECUTION  Agent completed → Human reviews → Audit is closed

Approval states:

    PENDING → APPROVED → (ADO issued, agent executes)
    PENDING → DENIED   → (DeniedDecision returned)
    PENDING → TIMEOUT  → (treated as DENIED, DIS signal emitted)
    APPROVED → REVOKED → (kill signal sent to active chain node)

The human is not in the execution path.
The human defines when they want to be consulted, and the system enforces it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    REVOKED = "revoked"  # approved, but revoked before/during execution


class InterventionPoint(str, Enum):
    PRE_EXECUTION = "pre_execution"
    MID_EXECUTION = "mid_execution"
    POST_EXECUTION = "post_execution"


@dataclass
class ApprovalRequest:
    """
    An approval request sent to a human authority.

    Contains everything the human needs to make a decision:
    - What the agent wants to do (decision_type, target, intent)
    - Why (evidence, assumptions, confidence)
    - What happens if approved (scope, blast_radius, reversibility)
    - What happens if denied (agent is blocked)
    - How long they have to decide (timeout_at)
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str = ""
    decision_type: str = ""
    proposed_by: str = ""
    target: str = ""
    intent: str = ""
    blast_radius: str = ""
    reversibility: bool = True
    effective_dsal: int = 0  # computed by RiskPipeline, not declared by agent
    evidence_summary: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    confidence: float = 0.0
    parent_decision_id: str | None = None

    intervention_point: InterventionPoint = InterventionPoint.PRE_EXECUTION
    required_authority: str = ""  # e.g. "SOC-Analyst", "SecOps-Lead"
    timeout_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc) + timedelta(minutes=15)
    )

    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_note: str = ""

    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) > self.timeout_at

    def approve(self, authority: str, note: str = "") -> None:
        if self.status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot approve: status is {self.status}")
        self.status = ApprovalStatus.APPROVED
        self.decided_by = authority
        self.decided_at = datetime.now(tz=timezone.utc)
        self.decision_note = note

    def deny(self, authority: str, note: str = "") -> None:
        if self.status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot deny: status is {self.status}")
        self.status = ApprovalStatus.DENIED
        self.decided_by = authority
        self.decided_at = datetime.now(tz=timezone.utc)
        self.decision_note = note

    def revoke(self, authority: str, note: str = "") -> None:
        if self.status != ApprovalStatus.APPROVED:
            raise ValueError(f"Cannot revoke: status is {self.status}")
        self.status = ApprovalStatus.REVOKED
        self.decided_by = authority
        self.decided_at = datetime.now(tz=timezone.utc)
        self.decision_note = note

    def expire(self) -> None:
        if self.status == ApprovalStatus.PENDING:
            self.status = ApprovalStatus.TIMEOUT

    def to_display_dict(self) -> dict[str, Any]:
        """Human-readable summary for display in any UI/channel."""
        return {
            "request_id": self.request_id[:8],
            "decision_id": self.decision_id[:8],
            "agent": self.proposed_by,
            "action": f"{self.decision_type} → {self.target}",
            "intent": self.intent,
            "blast_radius": self.blast_radius,
            "reversible": self.reversibility,
            "dsal_effective": self.effective_dsal,
            "confidence": f"{self.confidence:.0%}",
            "evidence": self.evidence_summary,
            "assumptions": self.assumptions,
            "authority_needed": self.required_authority,
            "timeout": self.timeout_at.strftime("%H:%M:%S UTC"),
            "status": self.status.value,
            "parent": self.parent_decision_id[:8] if self.parent_decision_id else None,
        }
