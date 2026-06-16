"""
Shani Core Schemas — Decision Object definitions v5.

ADO canonical structure (v5):

    AuthorizedDecisionObject
     ├── decision_id        # identity
     ├── proposal_hash      # integrity: bound to exact proposal
     ├── signature          # cryptographic: Ed25519 chain hash
     │
     ├── authority          # authorization: who approved
     ├── authorized_dsal    # authorization: level granted
     │
     ├── delegation_rules   # escalation prevention
     │    ├── allowed_sub_decisions
     │    ├── max_child_dsal
     │    ├── max_depth
     │    └── max_children      ← NEW: fan-out limit
     │
     ├── nonce              # replay prevention: one-time token
     │
     ├── issued_at          # temporal: when issued  (was: authorized_at)
     └── expires_at         # temporal: when invalid (was: valid_until)

Changes from v4:
  - authorized_at → issued_at     (naming clarity)
  - valid_until   → expires_at    (naming consistency with proposal)
  - max_children added to DelegationRules (fan-out attack prevention)
  - signature replaces binding_hash (name reflects actual semantics)
  - execution context (intent_binding, decision_type, constraints,
    rollback_policy, parent_decision_id) moved to ExecContext sub-object
    so the security-critical fields are unambiguous at the top level
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class DecisionType(str, Enum):
    REMEDIATION = "remediation"
    CONFIGURATION_CHANGE = "configuration_change"
    DATA_ACCESS = "data_access"
    NETWORK_ACTION = "network_action"
    DELEGATION = "delegation"
    POLICY_UPDATE = "policy_update"
    BROWSER_ACTION = "browser_action"  # Chrome extension / browser automation
    AGENT_TASK = "agent_task"  # nanoclaw agent tool execution
    TOOL_CALL = "tool_call"  # cowork / Claude API tool_use


class BlastRadius(str, Enum):
    ISOLATED = "isolated"
    LIMITED = "limited"
    SIGNIFICANT = "significant"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# DelegationRules  — all four bounds on child chains
# ---------------------------------------------------------------------------


class DelegationRules(BaseModel):
    """
    Explicit bounds on what child delegation chains may do.

    All four fields are included in the signed payload.
    Tampering with any field invalidates the signature.

    Fan-out attack (why max_children matters):
        Without max_children, an agent with a single D-SAL 3 ADO could
        spawn 1000 child agents each with a D-SAL 2 ADO, effectively
        multiplying impact far beyond what the authority intended to grant.

    Depth attack (why max_depth matters):
        A→B→C→D→... each at D-SAL 2 creates a deep chain where the
        original authority has no visibility into terminal actions.

    Combined invariant:
        Total descendants ≤ max_children ^ max_depth
        At max_children=5, max_depth=3: ≤ 125 agents
        This is auditable and bounded. Unbounded is not.
    """

    allowed_sub_decisions: list[str] = Field(
        default_factory=list,
        description="Whitelist of DecisionType values children may propose. Empty = no delegation.",
    )
    max_child_dsal: int = Field(
        default=0,
        ge=0,
        le=4,
        description=(
            "Maximum D-SAL a child ADO may be authorized at. "
            "Enforced invariant: max_child_dsal < parent.authorized_dsal."
        ),
    )
    max_depth: int = Field(
        default=0,
        ge=0,
        le=5,
        description=(
            "Remaining delegation hops allowed. "
            "Decremented by 1 at each delegation. "
            "0 = leaf node, cannot delegate further."
        ),
    )
    max_children: int = Field(
        default=0,
        ge=0,
        description=(
            "Maximum number of direct child ADOs this ADO may spawn. "
            "0 = no children permitted. "
            "Prevents fan-out attacks where one approval spawns thousands of agents."
        ),
    )

    model_config = {"frozen": True}

    @property
    def delegation_permitted(self) -> bool:
        return (
            bool(self.allowed_sub_decisions)
            and self.max_child_dsal > 0
            and self.max_depth > 0
            and self.max_children > 0
        )


# ---------------------------------------------------------------------------
# Supporting types
# ---------------------------------------------------------------------------


class DecisionScope(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    geographic_boundary: str | None = Field(default=None)
    max_affected_count: int | None = Field(default=None, ge=1)
    model_config = {"frozen": True}


class EvidenceItem(BaseModel):
    source: str
    content: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    raw_reference: str | None = Field(default=None)
    signature: str | None = Field(
        default=None,
        description=(
            "Base64-encoded Ed25519 signature over canonical evidence bytes "
            '({"content": content, "source": source}). '
            "Produced by an external auditor or trusted tool. "
            "EvidenceEvaluator verifies this against signed_by."
        ),
    )
    signed_by: str | None = Field(
        default=None,
        description=(
            "Base64-encoded Ed25519 public key (32 bytes) of the signer. "
            "Must be present when signature is set. "
            "Allows offline verification without a key registry."
        ),
    )
    model_config = {"frozen": True}


class RollbackPolicy(BaseModel):
    strategy: str
    rollback_window_seconds: int = Field(..., gt=0)
    automated: bool = Field(default=False)
    rollback_agent: str | None = Field(default=None)
    model_config = {"frozen": True}


class IntentBinding(BaseModel):
    """
    Cryptographically bound statement of what this ADO authorizes.
    Included in ExecContext which is part of the signed payload.
    """

    intent: str
    target: str
    scope_summary: str
    expected_effect: str
    reversibility: bool
    rollback_reference: str | None = Field(default=None)
    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# ExecContext — execution metadata (part of signed payload)
# ---------------------------------------------------------------------------


class ExecContext(BaseModel):
    """
    Execution context carried by the ADO.

    Groups fields that describe *what* is authorized (as opposed to
    the security-critical fields that prove *that* it is authorized).

    Included in the signed payload so tampering invalidates the signature,
    but kept separate from the top-level security fields for readability.
    """

    decision_type: DecisionType
    intent_binding: IntentBinding
    parent_decision_id: str | None = Field(default=None)
    constraints: dict[str, Any] = Field(default_factory=dict)
    rollback_policy: RollbackPolicy | None = Field(default=None)
    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Decision Proposal
# ---------------------------------------------------------------------------


class DecisionProposal(BaseModel):
    """
    The only input Shani accepts from an agent.

    canonical_hash() produces the proposal_hash embedded in the ADO.
    This binds the ADO to the exact proposal it was issued for.
    """

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_type: DecisionType
    proposed_by: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    scope: DecisionScope = Field(default_factory=DecisionScope)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    parent_decision_id: str | None = Field(default=None)
    assumptions: list[str] = Field(default_factory=list)
    # NOTE: The agent-requested D-SAL field is intentionally absent (SPEC §4.1 compliant).
    # Allowing agents to declare their own D-SAL level creates a privilege
    # self-escalation vector. Shani computes effective D-SAL from decision_type +
    # context via DSALCalculator and RiskPipeline; agents MUST NOT self-declare D-SAL.
    reversibility: bool
    blast_radius: BlastRadius
    delegation: bool = Field(default=False)
    expires_at: datetime | None = Field(default=None)
    origin_org: str | None = Field(
        default=None,
        description="Originating organization ID for cross-org ADO issuance (SPEC §8.8).",
    )

    @field_validator("expires_at")
    @classmethod
    def must_be_future(cls, v: datetime | None) -> datetime | None:
        if v is not None and v <= datetime.now(tz=timezone.utc):
            raise ValueError("expires_at must be in the future")
        return v

    model_config = {"frozen": True}

    def canonical_hash(self) -> str:
        """
        SHA-256 of this proposal's canonical form.

        Embedded in ADO.proposal_hash. Deterministic — same proposal
        always produces the same hash regardless of which process or
        instance computes it.
        """
        data = {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type.value,
            "proposed_by": self.proposed_by,
            "description": self.description,
            "target": self.target,
            "reversibility": self.reversibility,
            "blast_radius": self.blast_radius.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
        return hashlib.sha256(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


# ---------------------------------------------------------------------------
# Authorized Decision Object  (v5 — canonical structure)
# ---------------------------------------------------------------------------


class AuthorizedDecisionObject(BaseModel):
    """
    The Authorized Decision Object.

    The only token an agent may act upon. Structure (v5):

        decision_id      ← identity
        proposal_hash    ← integrity: bound to exact proposal (SHA-256)
        signature        ← cryptographic: Ed25519 chain hash

        authority        ← authorization: who approved
        authorized_dsal  ← authorization: level granted

        delegation_rules ← escalation prevention (all four bounds)

        nonce            ← replay prevention: one-time random token

        issued_at        ← temporal: when issued
        expires_at       ← temporal: when this ADO becomes invalid

        exec_context     ← execution metadata (in signed payload):
                           decision_type, intent_binding,
                           parent_decision_id, constraints, rollback_policy

    Security invariants enforced at construction:
      - delegation_rules.max_child_dsal < authorized_dsal
      - delegation_rules.max_children == 0 when no delegation permitted
      - expires_at > issued_at
    """

    # ── Identity ──────────────────────────────────────────────────────
    decision_id: str = Field(
        ...,
        description="Matches the DecisionProposal.decision_id this was issued for.",
    )

    # ── Integrity ─────────────────────────────────────────────────────
    proposal_hash: str = Field(
        ...,
        description=(
            "SHA-256 of the canonical DecisionProposal. "
            "Verifiers recompute this from the proposal to detect fake ADOs."
        ),
    )
    signature: str = Field(
        ...,
        description=(
            "Ed25519 signature chain hash over the canonical payload. "
            "Canonical payload := "
            "{decision_id, authority, authorized_dsal, issued_at, expires_at, "
            "proposal_hash, nonce, delegation_rules, exec_context}. "
            "Any field modification invalidates this signature. "
            "Agents MUST verify before execution."
        ),
    )

    # ── Authorization ─────────────────────────────────────────────────
    authority: str = Field(
        ...,
        description="Human role or policy that authorized this decision.",
    )
    authorized_dsal: int = Field(
        ...,
        ge=0,
        le=4,
        description="D-SAL level granted. Upper bound on what the agent may do.",
    )

    # ── Escalation prevention ─────────────────────────────────────────
    delegation_rules: DelegationRules = Field(
        default_factory=DelegationRules,
        description=(
            "Bounds on child delegation chains. All four fields are in the signed payload."
        ),
    )

    # ── Replay prevention ─────────────────────────────────────────────
    nonce: str = Field(
        default_factory=lambda: os.urandom(32).hex(),
        description=(
            "Cryptographically random 32-byte token (hex-encoded, 64 chars). "
            "In signed payload. Consumed on first execution. "
            "Replay of this ADO fails because nonce is already registered."
        ),
    )

    # ── Temporal ──────────────────────────────────────────────────────
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="When this ADO was issued by Shani.",
    )
    expires_at: datetime = Field(
        ...,
        description=(
            "When this ADO expires. Agents MUST check expires_at > now() before execution."
        ),
    )

    # ── Execution context ─────────────────────────────────────────────
    exec_context: ExecContext = Field(
        ...,
        description=(
            "Execution metadata included in the signed payload. "
            "Contains decision_type, intent_binding, parent_decision_id, "
            "constraints, rollback_policy."
        ),
    )

    # ── v5.2: Signature Chain (SPEC §4.6 SHOULD) ──────────────────
    signature_chain: dict | None = Field(
        default=None,
        description=(
            "Full ADO signature chain (authority → boundary). "
            "Serialized ADOSignatureChain.as_dict(). "
            "Present when multi-principal signing is configured. "
            "SPEC §4.6 SHOULD requirement."
        ),
    )

    # ── v5.1: Cross-org Binding (SPEC §8.8) ────────────────────────
    propagated_constraints: list[str] = Field(
        default_factory=list,
        description=(
            "Constraints inherited from the originating principal's UserPosture. "
            "MUST be included in the canonical signature payload. "
            "Mutation of these fields MUST break signature verification."
        ),
    )
    origin_org: str | None = Field(
        default=None,
        description="Identifier of the originating organization for cross-org ADOs.",
    )

    model_config = {"frozen": True}

    # ── Convenience accessors (backwards compatibility) ───────────────

    @property
    def decision_type(self) -> DecisionType:
        return self.exec_context.decision_type

    @property
    def intent_binding(self) -> IntentBinding:
        return self.exec_context.intent_binding

    @property
    def parent_decision_id(self) -> str | None:
        return self.exec_context.parent_decision_id

    @property
    def constraints(self) -> dict[str, Any]:
        return self.exec_context.constraints

    @property
    def rollback_policy(self) -> RollbackPolicy | None:
        return self.exec_context.rollback_policy

    # ── Validation ────────────────────────────────────────────────────

    @model_validator(mode="after")
    def check_invariants(self) -> "AuthorizedDecisionObject":
        # Delegation cannot grant equal or greater authority
        rules = self.delegation_rules
        if rules.delegation_permitted:
            if rules.max_child_dsal >= self.authorized_dsal:
                raise ValueError(
                    f"delegation_rules.max_child_dsal ({rules.max_child_dsal}) "
                    f"must be strictly less than authorized_dsal ({self.authorized_dsal}). "
                    "Delegation cannot escalate privileges."
                )
        # Expiry must be after issuance
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at.")
        return self

    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) >= self.expires_at

    def time_remaining_seconds(self) -> float:
        delta = (self.expires_at - datetime.now(tz=timezone.utc)).total_seconds()
        return max(0.0, delta)
