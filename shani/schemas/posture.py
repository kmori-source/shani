"""
Shani v0.4 Posture Layer Schemas.

Defines the Binding layer: UserPosture, PostureConstraints,
PostureRefinementRequest, and PostureSimulationResult.

These are first-class schema objects, not subtypes of DeniedDecision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PostureOutcome(str, Enum):
    """Result of PostureEngine evaluation."""

    PASS = "PASS"
    REJECT = "REJECT"
    AMBIGUOUS = "AMBIGUOUS"


class PostureConstraints(BaseModel):
    """
    Constraints declared by a principal in their UserPosture.

    These define the boundary of actions the principal accepts responsibility for.
    Must remain within OrgPolicy.absolute_constraints.
    """

    target_scope: str = Field(
        ..., description="Regex or glob pattern for allowed targets, e.g. 'host:dev-*'"
    )
    max_blast_radius: str = Field(
        ..., description="Maximum blast radius: isolated | limited | significant | critical"
    )
    reversibility_required: bool = Field(
        ..., description="If true, irreversible proposals are REJECTED"
    )
    minimum_evidence: int = Field(
        ..., ge=0, description="Minimum number of evidence items required"
    )

    model_config = {"frozen": True}


class PostureHistoryEntry(BaseModel):
    """Immutable record of a previous posture version. Must not be deleted."""

    version: str
    signed_at: datetime
    note: str = ""

    model_config = {"frozen": True}


class UserPosture(BaseModel):
    """
    The structured expression of a principal's Binding.

    Declares constraints within which an agent's proposals are considered
    within scope. Owned by the individual principal. Must be signed.
    Must remain within OrgPolicy.absolute_constraints.

    Normative requirements (SPEC §8.2):
    - Must contain simulation_ref referencing a PostureSimulationResult
    - Must not exceed OrgPolicy.absolute_constraints
    - history entries are immutable after creation
    - posture_signature: Ed25519/HMAC signature over canonical_content() (SPEC §8.2, §8.7)
    """

    version: str
    principal_id: str
    signed_at: datetime
    intent_statement: str
    simulation_ref: str  # must reference PostureSimulationResult
    constraints: PostureConstraints
    history: tuple[PostureHistoryEntry, ...] = Field(default_factory=tuple)
    posture_signature: str | None = None  # base64 Ed25519/HMAC-SHA256 signature

    model_config = {"frozen": True}

    def canonical_content(self) -> dict:
        """Return the canonical dict payload that is signed (excludes posture_signature)."""
        return {
            "version": self.version,
            "principal_id": self.principal_id,
            "signed_at": self.signed_at.isoformat(),
            "intent_statement": self.intent_statement,
            "simulation_ref": self.simulation_ref,
            "constraints": {
                "target_scope": self.constraints.target_scope,
                "max_blast_radius": self.constraints.max_blast_radius,
                "reversibility_required": self.constraints.reversibility_required,
                "minimum_evidence": self.constraints.minimum_evidence,
            },
        }

    def sign(self, keypair: Any, simulation_store: dict) -> "UserPosture":
        """Return a new UserPosture with a cryptographic signature (Ed25519/HMAC-SHA256).

        simulation_store: required mapping of simulation_id → PostureSimulationResult.
        Raises ValueError if simulation_ref is not found in the store (SPEC §8.6 MUST).
        """
        if self.simulation_ref not in simulation_store:
            raise ValueError(
                f"UserPosture simulation_ref '{self.simulation_ref}' does not reference a "
                "known PostureSimulationResult (SPEC §8.6). "
                "Run PostureSimulation before signing."
            )
        import json as _json
        import base64 as _b64
        from ..crypto.signing import ADOSigner

        signer = ADOSigner(keypair)
        canonical = _json.dumps(
            self.canonical_content(), sort_keys=True, separators=(",", ":")
        ).encode()
        sig_bytes = signer._sign_raw(canonical)
        return self.model_copy(update={"posture_signature": _b64.b64encode(sig_bytes).decode()})

    def verify_signature(self, public_key_bytes: bytes) -> bool:
        """Verify posture_signature against the principal's Ed25519 public key."""
        if self.posture_signature is None:
            return False
        import json as _json
        import base64 as _b64
        from ..crypto.signing import ADOChainVerifier

        canonical = _json.dumps(
            self.canonical_content(), sort_keys=True, separators=(",", ":")
        ).encode()
        try:
            sig_bytes = _b64.b64decode(self.posture_signature)
            ADOChainVerifier._verify_raw(public_key_bytes, canonical, sig_bytes)
            return True
        except Exception:
            return False

    @classmethod
    def update_posture(
        cls,
        previous: "UserPosture",
        version: str,
        signed_at: datetime,
        intent_statement: str,
        simulation_ref: str,
        constraints: PostureConstraints,
        update_note: str = "",
    ) -> "UserPosture":
        """
        Create a new UserPosture version, preserving history (SPEC §8.7).

        Appends the previous version to history before creating the new instance.
        Use this instead of constructing UserPosture directly when updating a posture.
        """
        history_entry = PostureHistoryEntry(
            version=previous.version,
            signed_at=previous.signed_at,
            note=update_note,
        )
        new_history = previous.history + (history_entry,)
        return cls(
            version=version,
            principal_id=previous.principal_id,
            signed_at=signed_at,
            intent_statement=intent_statement,
            simulation_ref=simulation_ref,
            constraints=constraints,
            history=new_history,
        )


# ---------------------------------------------------------------------------
# PostureRefinementRequest — first-class evaluation outcome (NOT DeniedDecision)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostureRefinementRequest:
    """
    First-class evaluation outcome from PostureEngine.

    Returned when PostureEngine cannot determine if a proposal is within scope
    (AMBIGUOUS result from Layer 2). Distinct from DeniedDecision: the proposal
    is not denied — it requires the principal to refine their Posture.

    Expected agent behavior (SPEC §8.5):
    1. Halt the proposed operation (same as DeniedDecision)
    2. Notify principal_id via a separate channel (not HITL)
    3. Do NOT retry until principal updates and re-signs their Posture
    4. Log with full context for audit
    """

    proposal_id: str
    principal_id: str
    ambiguity: str
    matched_constraints: list[str]
    unresolved: list[str]
    suggested_update: str | None = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


# ---------------------------------------------------------------------------
# PostureSimulationResult — required before signing a UserPosture
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostureSimulationResult:
    """
    Result of running a candidate UserPosture against historical proposals.

    Required before a principal may sign or update a UserPosture (SPEC §8.6).
    Prevents Binding Theater: signing without understanding operational consequences.

    A conforming implementation MUST:
    - Include pass_count, reject_count, ambiguous_count
    - Include at least 3 reject_examples if any rejections exist
    - Include a delta_vs_current comparison if current posture exists
    """

    simulation_id: str
    posture_version: str
    principal_id: str
    pass_count: int
    reject_count: int
    ambiguous_count: int
    reject_examples: list[dict[str, Any]]
    pass_examples: list[dict[str, Any]]
    ambiguous_examples: list[dict[str, Any]]
    delta_vs_current: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
