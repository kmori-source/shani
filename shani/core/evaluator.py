"""
Shani Core Evaluator v4.

Security changes from v3:
  ① Canonical payload now includes proposal_hash, nonce, delegation_rules.
     Fake ADOs cannot pass verify_binding() without the original proposal.

  ② register_executed() now calls nonce_store.consume().
     Replay attacks fail even after process restart (with FileNonceStore).
     verify_binding() checks nonce store before returning True.

  ③ _issue_ado() enforces DelegationRules anti-escalation invariant:
     max_child_dsal must be < authorized_dsal.
     Child ADO validation checks parent's delegation_rules before authorizing.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from ..schemas.decision import (
    AuthorizedDecisionObject,
    DecisionProposal,
    DecisionType,
    DelegationRules,
    ExecContext,
    IntentBinding,
    RollbackPolicy,
)
from ..schemas.state import DIS, DSAL, DISStateMachine
from ..schemas.posture import PostureRefinementRequest, UserPosture
from ..crypto.signing import ADOChainVerifier, ADOSignatureChain, ADOSigner, SigningKeypair
from ..integrity.monitor import DISIntegrityMonitor, IntegritySignal
from ..authority.policy import DecisionPolicyProvider
from ..authority.dsal_calculator import DSALCalculator
from ..risk.pipeline import RiskPipeline, PipelineResult
from ..risk.decision_space import Alternative
from ..posture.engine import PostureEngine
from ..security.replay_store import InMemoryNonceStore, NonceAlreadyConsumed, NonceStore

logger = logging.getLogger("shani.evaluator")


@dataclass(frozen=True)
class DeniedDecision:
    """
    Returned when Shani denies a proposal.

    Carries a DenialContext explaining why the proposal was denied.
    The HITL gate converts this into an ApprovalRequest and presents it to humans.
    """
    decision_id: str
    reason: str
    denied_at: datetime = None
    context: object = None          # DenialContext (typed as object to avoid circular import)
    pipeline_result: object = None  # snapshot of PipelineResult
    proposal: object = None         # snapshot of DecisionProposal

    def __post_init__(self):
        object.__setattr__(self, "denied_at", datetime.now(tz=timezone.utc))

    def to_human_summary(self) -> dict:
        """Human-readable denial summary. Used for HITL notifications."""
        summary: dict = {
            "reason":      self.reason,
            "decision_id": self.decision_id[:8] if self.decision_id else None,
            "denied_at":   self.denied_at.isoformat() if self.denied_at else None,
        }
        if self.pipeline_result is not None:
            pr = self.pipeline_result
            summary["risk_score"] = round(pr.risk_score.aggregate, 3)
            summary["effective_dsal"] = pr.effective_dsal
            if pr.rule_result.applied_rules:
                summary["rules_triggered"] = pr.rule_result.applied_rules
            if pr.evidence_eval.flags:
                summary["evidence_flags"] = list(pr.evidence_eval.flags.keys())
            if pr.decision_space.framing_risk_score > 0.1:
                summary["framing_risk"] = round(pr.decision_space.framing_risk_score, 3)
            summary["risk_breakdown"] = {
                d.name: round(d.score, 3)
                for d in pr.risk_score.dimensions
            }
        if self.proposal is not None:
            summary["proposal"] = {
                "decision_type":  self.proposal.decision_type.value,
                "target":         self.proposal.target,
                "blast_radius":   self.proposal.blast_radius.value,
                "reversibility":  self.proposal.reversibility,
                "evidence_count": len(self.proposal.evidence),
                "confidence":     self.proposal.confidence,
            }
        return summary


EvaluationResult = AuthorizedDecisionObject | DeniedDecision | PostureRefinementRequest


class AuthorityProvider(Protocol):
    def resolve_authority(self, effective_dsal: int) -> str: ...
    def max_authorized_dsal(self) -> int: ...


class ShaniEvaluator:
    """
    Shani Evaluator v4.

    Security model:
      - Every ADO is bound to its proposal via proposal_hash (Fix ①)
      - Every ADO carries a one-time nonce consumed on execution (Fix ②)
      - Delegation chains are bounded by DelegationRules (Fix ③)
      - Agent chains cannot escalate privileges recursively
    """

    def __init__(
        self,
        authority_provider:       AuthorityProvider,
        decision_policy:          DecisionPolicyProvider | None = None,
        boundary_keypair:         SigningKeypair | None = None,
        authority_keypair:        SigningKeypair | None = None,
        dis_machine:              DISStateMachine | None = None,
        integrity_monitor:        DISIntegrityMonitor | None = None,
        nonce_store:              NonceStore | None = None,
        default_validity_seconds: int = 300,
        kill_switch:              bool = False,
        user_posture:             UserPosture | None = None,
        org_id:                   str | None = None,
    ) -> None:
        self._authority    = authority_provider
        self._policy       = decision_policy or DecisionPolicyProvider(allow_unregistered_agents=True)
        self._dis          = dis_machine or DISStateMachine()
        self._monitor      = integrity_monitor or DISIntegrityMonitor(self._dis)
        self._nonce_store  = nonce_store if nonce_store is not None else InMemoryNonceStore()
        self._default_validity = default_validity_seconds
        self._kill_switch  = kill_switch or bool(os.environ.get("SHANI_KILL_SWITCH")) or self._policy.kill_switch_enabled
        self._user_posture = user_posture  # v0.4: optional PostureEngine stage
        self._org_id       = org_id        # v5.1: org identity for cross-org ADO issuance

        self._boundary_keypair  = boundary_keypair  or self._default_keypair("shani-boundary")
        self._authority_keypair = authority_keypair or self._default_keypair("shani-authority")
        self._boundary_signer   = ADOSigner(self._boundary_keypair)
        self._authority_signer  = ADOSigner(self._authority_keypair)
        # environment_rules sourced from policy (not hardcoded)
        env_rules = getattr(self._policy, "_environment_rules", None)
        self._dsal_calculator   = DSALCalculator(environment_rules=env_rules)
        self._risk_pipeline     = RiskPipeline()
        # Fan-out tracking: counts direct children issued per parent ADO decision_id
        self._child_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def dis(self) -> DIS:
        return self._dis.state

    @property
    def boundary_public_key_b64(self) -> str:
        import base64
        return base64.b64encode(self._boundary_keypair.public_key_bytes).decode()

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        proposal: DecisionProposal,
        parent_ado: AuthorizedDecisionObject | None = None,
    ) -> EvaluationResult:
        """
        Evaluate a DecisionProposal.

        parent_ado: If this is a delegated decision, pass the parent ADO.
                    Shani will enforce DelegationRules from the parent.
        """

        # 1. Kill switch
        if self._kill_switch:
            return DeniedDecision(proposal.decision_id, "Kill switch active.")

        # 2. DIS gate
        if not self._dis.state.allows_execution:
            return DeniedDecision(
                proposal.decision_id,
                f"DIS is {self._dis.state.value}. Execution suspended.",
            )

        # 2b. OrgPolicy prod_reversibility check (SPEC §8.3)
        prod_denied = self._check_prod_reversibility(proposal)
        if prod_denied:
            return prod_denied

        # 3. Replay: check decision_id in nonce store
        #    (nonce itself is checked at execution time via register_executed)
        signal = self._monitor.check_replay(proposal.decision_id)
        if signal is not None:
            self._monitor.process(signal)
            return DeniedDecision(proposal.decision_id, signal.detail)

        # 4. Expiry
        if proposal.expires_at:
            expires_at = proposal.expires_at
            if isinstance(expires_at, str):
                # pydantic shim does not coerce ISO strings to datetime; handle defensively
                expires_at = datetime.fromisoformat(expires_at)
            if datetime.now(tz=timezone.utc) > expires_at:
                return DeniedDecision(proposal.decision_id, "Proposal has expired.")

        # 5a. PostureEngine (v0.4) — inserted before RiskPipeline (SPEC §8.4)
        #     If a UserPosture is configured, evaluate the proposal against it.
        #     REJECT → DeniedDecision; AMBIGUOUS → PostureRefinementRequest; PASS → continue.
        if self._user_posture is not None:
            from ..schemas.posture import PostureOutcome
            posture_engine = PostureEngine(
                self._user_posture,
                risk_pipeline=self._risk_pipeline,
                org_policy=self._policy.org_policy,
            )
            posture_outcome, refinement_request = posture_engine.evaluate(proposal)
            if posture_outcome == PostureOutcome.REJECT:
                logger.warning(
                    "POSTURE REJECT | decision=%s reason=outside_posture_constraints",
                    proposal.decision_id[:8],
                )
                return DeniedDecision(
                    decision_id=proposal.decision_id,
                    reason="Proposal rejected by PostureEngine: outside UserPosture constraints.",
                    proposal=proposal,
                )
            if posture_outcome == PostureOutcome.AMBIGUOUS:
                logger.info(
                    "POSTURE AMBIGUOUS | decision=%s → PostureRefinementRequest",
                    proposal.decision_id[:8],
                )
                return refinement_request

        # 5b. Risk Pipeline: compute effective D-SAL via 4 components
        #     Agents do not declare their own D-SAL. Shani computes it.
        #     Fail-safe: if the pipeline itself raises (e.g. LLM timeout, parse error,
        #     unexpected exception), deny the proposal rather than letting the agent
        #     proceed without governance. "Fail closed" is the only safe default for
        #     an autonomous-agent governance layer.
        try:
            base_dsal = self._policy.required_dsal(proposal.decision_type)
            alternatives = getattr(proposal, '_alternatives', None)
            pipeline_result = self._risk_pipeline.evaluate(proposal, base_dsal, alternatives)
        except Exception as exc:
            logger.error(
                "RiskPipeline FAILURE | decision=%s error=%s — denying proposal (fail-safe)",
                proposal.decision_id[:8], exc,
            )
            return DeniedDecision(
                decision_id=proposal.decision_id,
                reason=(
                    "Governance pipeline evaluation failed. "
                    "Proposal denied as a safety measure (fail-safe). "
                    f"Error: {type(exc).__name__}: {exc}"
                ),
                proposal=proposal,
            )

        logger.info(
            "RiskPipeline | decision=%s\n%s",
            proposal.decision_id[:8], pipeline_result.explain(),
        )

        # rule engine: immediate DENY (hard rule)
        if pipeline_result.is_hard_denied:
            rule_name = (
                pipeline_result.rule_result.final_deny.rule_name
                if pipeline_result.rule_result.final_deny else "unknown"
            )
            logger.warning(
                "HARD DENY | decision=%s rule=%s reason=%s",
                proposal.decision_id[:8], rule_name, pipeline_result.deny_reason,
            )
            return DeniedDecision(
                decision_id=proposal.decision_id,
                reason=f"Hard rule denied: {pipeline_result.deny_reason}",
                pipeline_result=pipeline_result,
                proposal=proposal,
            )

        effective = pipeline_result.effective_dsal

        # 6. Agent authorization against effective D-SAL
        allowed, reason = self._policy.authorize(
            proposal.proposed_by, proposal.decision_type, effective
        )
        if not allowed:
            return DeniedDecision(
                decision_id=proposal.decision_id,
                reason=reason,
                pipeline_result=pipeline_result,
                proposal=proposal,
            )

        # 7. Evidence requirement for effective D-SAL 2+
        # Guard: only require evidence when risk factors OTHER than missing evidence
        # elevate D-SAL to 2+. Without this guard, no_evidence (+1) would circularly
        # elevate D-SAL → require evidence → impossible to satisfy for low-risk ops.
        if effective >= 2 and not proposal.evidence:
            effective_without_evidence_penalty = effective - 1
            if effective_without_evidence_penalty >= 2:
                return DeniedDecision(
                    decision_id=proposal.decision_id,
                    reason=(
                        f"Effective D-SAL {effective} requires structured evidence. "
                        f"risk_score={pipeline_result.risk_score.aggregate:.2f}"
                    ),
                    pipeline_result=pipeline_result,
                    proposal=proposal,
                )

        # 8. Delegation constraint
        if proposal.delegation and not DSAL(effective).allows_delegation:
            return DeniedDecision(
                proposal.decision_id,
                f"Effective D-SAL {effective} does not permit delegation.",
            )

        # 9. Global D-SAL ceiling
        max_dsal = self._authority.max_authorized_dsal()
        if effective > max_dsal:
            return DeniedDecision(
                proposal.decision_id,
                f"Effective D-SAL {effective} > ceiling {max_dsal}.",
            )

        # 10. Parent delegation rules enforcement
        if parent_ado is not None:
            denied = self._check_delegation_rules_eff(proposal, parent_ado, effective)
            if denied:
                return denied

        # 11. Issue ADO
        ado = self._issue_ado(proposal, parent_ado, effective)

        # Increment fan-out counter after successful issuance
        if parent_ado is not None:
            self._child_counts[parent_ado.decision_id] = (
                self._child_counts.get(parent_ado.decision_id, 0) + 1
            )

        return ado

    # ------------------------------------------------------------------
    # Fix ①: verify_binding now validates proposal_hash
    # ------------------------------------------------------------------

    def verify_binding(
        self,
        ado: AuthorizedDecisionObject,
        proposal: DecisionProposal | None = None,
    ) -> bool:
        """
        Verify ADO integrity. Four independent checks, all must pass.

        a) Expiry: reject ADOs past their expires_at timestamp.

        b) Signature: recompute HMAC/Ed25519 of canonical_payload and compare
           to ado.signature. Detects any field tampering.

        c) Proposal binding: if proposal provided, verify
           proposal.canonical_hash() == ado.proposal_hash.
           Detects fake ADOs (target swap, dsal escalation, etc).

        d) Replay guard: verify nonce has NOT been consumed.
           Detects replayed ADOs even after process restart.
        """
        # a) Expiry: reject ADOs that have already expired.
        #    This is checked first (cheap, no crypto) and prevents wasting
        #    work on an ADO that cannot legitimately be used.
        if ado.is_expired():
            logger.warning(
                "EXPIRED ADO | decision=%s expires_at=%s",
                ado.decision_id[:8], ado.expires_at.isoformat(),
            )
            return False

        # b) Signature: verify Ed25519 (or HMAC fallback) signature over canonical payload.
        #    Uses asymmetric verification via ADOChainVerifier so the private key is
        #    not needed at verify time. This enables offline ADO verification.
        payload = self._canonical_payload(ado)
        try:
            import json as _json
            import base64 as _b64
            canonical = _json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
            sig_bytes = _b64.b64decode(ado.signature)
            ADOChainVerifier._verify_raw(
                self._boundary_keypair.public_key_bytes,
                canonical,
                sig_bytes,
            )
        except Exception:
            logger.warning(
                "SIGNATURE MISMATCH | decision=%s sig_prefix=%s",
                ado.decision_id[:8], ado.signature[:12],
            )
            return False

        # c) Proposal binding
        if proposal is not None:
            if proposal.canonical_hash() != ado.proposal_hash:
                logger.error(
                    "FAKE ADO DETECTED | decision=%s "
                    "proposal_hash mismatch: ado=%s proposal=%s",
                    ado.decision_id[:8],
                    ado.proposal_hash[:16],
                    proposal.canonical_hash()[:16],
                )
                return False

        # d) Replay guard
        if self._nonce_store.is_consumed(ado.nonce):
            logger.warning(
                "REPLAY DETECTED | decision=%s nonce=%s",
                ado.decision_id[:8], ado.nonce[:16],
            )
            return False

        return True

    # ------------------------------------------------------------------
    # Fix ②: register_executed consumes nonce in persistent store
    # ------------------------------------------------------------------

    def register_executed(
        self,
        ado_or_id,
        agent_id: str = "",
    ) -> None:
        """
        Mark ADO as executed. Consumes the nonce (SPEC §5.4).

        Must be called after every successful execution.
        Raises NonceAlreadyConsumed if the ADO has been executed before.
        Raises TypeError if a string decision_id is passed (removed legacy path).
        """
        if isinstance(ado_or_id, str):
            # Removed non-conformant legacy path (SPEC §5.4).
            # Passing only a decision_id string skips nonce consumption and disables
            # replay prevention. Pass the full AuthorizedDecisionObject instead.
            raise TypeError(
                "register_executed(str) is not conformant with SPEC §5.4: "
                "string decision_id path has been removed to enforce replay prevention. "
                "Pass the full AuthorizedDecisionObject to consume the nonce."
            )
        ado = ado_or_id
        try:
            self._nonce_store.consume(
                nonce=ado.nonce,
                decision_id=ado.decision_id,
                agent_id=agent_id,
            )
            self._monitor.register_executed(ado.decision_id)
            logger.info("ADO executed + nonce consumed | decision=%s", ado.decision_id[:8])
        except NonceAlreadyConsumed as e:
            logger.error("REPLAY ATTEMPT BLOCKED | %s", e)
            raise

    def process_integrity_signal(self, signal: IntegritySignal) -> None:
        event = self._monitor.process(signal)
        logger.warning(
            "IntegritySignal | type=%s severity=%s dis=%s→%s",
            event.signal.signal_type.value, event.severity.value,
            event.dis_before.value, event.dis_after.value,
        )

    def activate_kill_switch(self) -> None:
        self._kill_switch = True

    def deactivate_kill_switch(self, justification: str, authorized_by: str) -> None:
        if not justification.strip() or not authorized_by.strip():
            raise ValueError("Deactivation requires justification and named authority.")
        self._kill_switch = False

    # ------------------------------------------------------------------
    # Fix ③: Delegation rules enforcement
    # ------------------------------------------------------------------

    def _check_delegation_rules_eff(
        self,
        proposal: DecisionProposal,
        parent_ado: AuthorizedDecisionObject,
        effective_dsal: int,
    ) -> "DeniedDecision | PostureRefinementRequest | None":
        """
        Enforce parent ADO's DelegationRules.
        Uses effective_dsal (calculator output), not requested_dsal.
        """
        # Cross-org enforcement FIRST (SPEC §8.8, §8.9).
        # SPEC §8.9 requires empty propagated_constraints to be treated as AMBIGUOUS
        # regardless of delegation rules — checked before allowed_sub_decisions.
        if parent_ado.origin_org is not None:
            # Empty propagated_constraints on a cross-org ADO MUST be AMBIGUOUS (SPEC §8.9).
            if not parent_ado.propagated_constraints:
                return PostureRefinementRequest(
                    proposal_id=proposal.decision_id,
                    principal_id=parent_ado.origin_org or "unknown-origin",
                    ambiguity=(
                        f"Cross-org ADO (origin_org={parent_ado.origin_org!r}) has no "
                        "propagated_constraints. Receiving Shani cannot validate cross-org scope."
                    ),
                    matched_constraints=[],
                    unresolved=["propagated_constraints"],
                    suggested_update=(
                        "Include propagated_constraints in the cross-org ADO to describe "
                        "the originating principal's UserPosture constraints."
                    ),
                )
            cross_org_min = self._policy.org_policy.absolute_constraints.cross_org_min_dsal
            if effective_dsal < cross_org_min:
                return DeniedDecision(
                    proposal.decision_id,
                    f"Cross-org transition requires minimum D-SAL {cross_org_min} "
                    f"(OrgPolicy.cross_org_min_dsal), but effective D-SAL is {effective_dsal}.",
                )
            # Validate propagated_constraints through PostureEngine (SPEC §8.8).
            # Unknown vocabulary or failed validation → PostureRefinementRequest (not DeniedDecision).
            refinement = self._validate_propagated_constraints_via_engine(
                proposal, parent_ado
            )
            if refinement is not None:
                return refinement

        rules = parent_ado.delegation_rules

        if not rules.allowed_sub_decisions:
            return DeniedDecision(
                proposal.decision_id,
                f"Parent ADO {parent_ado.decision_id[:8]} does not permit delegation.",
            )

        if proposal.decision_type.value not in rules.allowed_sub_decisions:
            return DeniedDecision(
                proposal.decision_id,
                f"Parent ADO does not permit '{proposal.decision_type.value}'. "
                f"Allowed: {rules.allowed_sub_decisions}",
            )

        # effective D-SAL escalation guard
        if effective_dsal > rules.max_child_dsal:
            return DeniedDecision(
                proposal.decision_id,
                f"Effective D-SAL {effective_dsal} exceeds parent's "
                f"max_child_dsal={rules.max_child_dsal}.",
            )

        if proposal.delegation and rules.max_depth <= 1:
            return DeniedDecision(
                proposal.decision_id,
                f"Parent ADO has max_depth={rules.max_depth}. No further delegation.",
            )

        # Fan-out enforcement: prevent one ADO from spawning more children than permitted
        if rules.max_children > 0:
            current_children = self._child_counts.get(parent_ado.decision_id, 0)
            if current_children >= rules.max_children:
                return DeniedDecision(
                    proposal.decision_id,
                    f"Parent ADO {parent_ado.decision_id[:8]} has reached its "
                    f"max_children limit ({rules.max_children}). "
                    "Fan-out attack prevention triggered.",
                )

        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _issue_ado(
        self,
        proposal: DecisionProposal,
        parent_ado: AuthorizedDecisionObject | None,
        effective_dsal: int,
    ) -> AuthorizedDecisionObject:
        authority_str  = self._authority.resolve_authority(effective_dsal)
        valid_until    = datetime.now(tz=timezone.utc) + timedelta(seconds=self._default_validity)
        constraints    = self._derive_constraints(proposal, effective_dsal)
        rollback       = self._build_rollback(proposal) if proposal.reversibility else None
        intent         = self._build_intent(proposal)
        deleg_rules    = self._build_delegation_rules(proposal, parent_ado, effective_dsal)
        proposal_hash  = proposal.canonical_hash()

        # Propagate cross-org fields (SPEC §8.8)
        origin_org: str | None = None
        propagated: list[str] = []
        if parent_ado is not None and parent_ado.origin_org is not None:
            # Inherit from parent ADO
            origin_org = parent_ado.origin_org
            propagated = list(parent_ado.propagated_constraints)
        elif parent_ado is None and self._user_posture is not None:
            # First ADO in chain: embed UserPosture constraints for cross-org consumers
            origin_org = self._org_id
            propagated = self._build_propagated_constraints(self._user_posture)
        elif parent_ado is None and proposal.origin_org is not None:
            # Explicit cross-org designation on the proposal
            origin_org = proposal.origin_org
            propagated = (
                self._build_propagated_constraints(self._user_posture)
                if self._user_posture is not None else []
            )

        # Build ADO (nonce auto-generated by schema default_factory)
        ado = AuthorizedDecisionObject(
            decision_id           = proposal.decision_id,
            authorized_dsal       = effective_dsal,
            authority             = authority_str,
            expires_at            = valid_until,
            proposal_hash         = proposal_hash,
            delegation_rules      = deleg_rules,
            signature             = "__pending__",
            propagated_constraints= propagated,
            origin_org            = origin_org,
            exec_context          = ExecContext(
                decision_type      = proposal.decision_type,
                intent_binding     = intent,
                parent_decision_id = proposal.parent_decision_id,
                constraints        = constraints,
                rollback_policy    = rollback,
            ),
        )

        payload      = self._canonical_payload(ado)
        binding_hash = self._compute_signature(payload)

        # Build multi-principal signature chain: authority → boundary (SPEC §4.6 SHOULD)
        chain = ADOSignatureChain()
        self._authority_signer.sign(payload, chain, role="authority")
        self._boundary_signer.sign(payload, chain, role="boundary")

        ado = ado.model_copy(update={
            "signature":       binding_hash,
            "signature_chain": chain.as_dict(),
        })

        logger.info(
            "ADO issued | id=%s type=%s dsal=%s nonce=%s binding=%s",
            ado.decision_id[:8], ado.exec_context.decision_type.value,
            ado.authorized_dsal, ado.nonce[:8], binding_hash[:12],
        )
        return ado

    def _compute_signature(self, payload: dict) -> str:
        """
        Compute a deterministic Ed25519 signature over the canonical payload.

        Uses ADOSigner._sign_raw() which selects Ed25519 when the cryptography
        package is available, and falls back to HMAC-SHA256 otherwise.
        Result is a base64-encoded string for compact storage in the ADO.

        Deterministic: Ed25519 with a fixed key produces the same signature
        for the same message. This is required for verify_binding() to work.
        """
        import json as _json
        import base64 as _b64
        canonical = _json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        sig_bytes = self._boundary_signer._sign_raw(canonical)
        return _b64.b64encode(sig_bytes).decode()

    @staticmethod
    def _canonical_payload(ado: "AuthorizedDecisionObject") -> dict:
        """
        Canonical signature payload = canonical_json(ADO minus signature).

        Invariant:
            signature = Sign(SHA256(canonical_json(this payload)))

        Covers every ADO field except `signature` itself.

        Attack vectors closed by full coverage:
            authority rewrite    → authority in payload → signature invalid
            dsal escalation      → authorized_dsal in payload → invalid
            delegation loosening → delegation_rules in payload → invalid
            execution drift      → exec_context in payload → invalid
              e.g. approved: isolate host A, executed: delete cluster
                   → intent_binding.target differs → signature fails
            nonce stripping      → nonce in payload → invalid
            expiry extension     → expires_at in payload → invalid
            issued_at backdating → issued_at in payload → invalid
        """
        ec = ado.exec_context
        dr = ado.delegation_rules
        return {
            # Identity
            "decision_id":     ado.decision_id,
            # Integrity
            "proposal_hash":   ado.proposal_hash,
            # Authorization
            "authority":       ado.authority,
            "authorized_dsal": ado.authorized_dsal,
            # Escalation prevention — all four bounds
            "delegation_rules": {
                "allowed_sub_decisions": sorted(dr.allowed_sub_decisions),
                "max_child_dsal":        dr.max_child_dsal,
                "max_depth":             dr.max_depth,
                "max_children":          dr.max_children,
            },
            # Replay prevention
            "nonce": ado.nonce,
            # Temporal
            "issued_at":  ado.issued_at.isoformat(),
            "expires_at": ado.expires_at.isoformat(),
            # Execution context — execution drift prevention
            # MUST be signed: covers decision_type, intent_binding.target,
            # scope, expected_effect, constraints, parent_decision_id.
            # Without this, an agent could substitute a different action
            # after approval.
            "exec_context": {
                "decision_type": ec.decision_type.value,
                "intent_binding": {
                    "intent":          ec.intent_binding.intent,
                    "target":          ec.intent_binding.target,
                    "scope_summary":   ec.intent_binding.scope_summary,
                    "expected_effect": ec.intent_binding.expected_effect,
                    "reversibility":   ec.intent_binding.reversibility,
                },
                "parent_decision_id": ec.parent_decision_id,
                "constraints":        ec.constraints,
                # rollback_policy: nullable nested object; omitted to avoid
                # serialisation ambiguity. Covered indirectly by proposal_hash.
            },
            # v5.1: cross-org propagated constraints (SPEC §8.8)
            # Included in signed payload — mutation breaks signature verification.
            "propagated_constraints": sorted(ado.propagated_constraints),
            "origin_org":             ado.origin_org,
        }


    def _build_delegation_rules(
        self,
        proposal: DecisionProposal,
        parent_ado: AuthorizedDecisionObject | None,
        effective_dsal: int = 0,
    ) -> DelegationRules:
        if not proposal.delegation:
            return DelegationRules(allowed_sub_decisions=[], max_child_dsal=0, max_depth=0)

        max_child = effective_dsal - 1
        if parent_ado is not None:
            max_child = min(max_child, parent_ado.delegation_rules.max_child_dsal - 1)
        max_child = max(0, max_child)

        # Inherit depth budget from parent, decrement by 1
        max_depth = 3  # default for root delegation
        if parent_ado is not None:
            max_depth = max(0, parent_ado.delegation_rules.max_depth - 1)

        # Derive allowed_sub_decisions from policy: include all DecisionTypes
        # whose required D-SAL is within the child's budget.
        # This ensures delegation cannot grant access to types requiring higher authority
        # than the child D-SAL allows (SPEC §4.3, §8.7).
        allowed: list[str] = [
            dt.value
            for dt in DecisionType
            if self._policy.required_dsal(dt) <= max_child
        ]

        # If the parent ADO restricts sub-decisions, intersect to prevent escalation.
        # Delegation chains must never broaden the allowed types granted by the root.
        if parent_ado is not None and parent_ado.delegation_rules.allowed_sub_decisions:
            parent_allowed = set(parent_ado.delegation_rules.allowed_sub_decisions)
            allowed = [dt for dt in allowed if dt in parent_allowed]

        return DelegationRules(
            allowed_sub_decisions=allowed,
            max_child_dsal=max_child,
            max_depth=max_depth,
            max_children=5,
        )

    def _build_intent(self, proposal: DecisionProposal) -> IntentBinding:
        scope = proposal.scope
        parts = []
        if scope.asset_ids:
            parts.append(f"assets:{','.join(scope.asset_ids)}")
        if scope.resource_types:
            parts.append(f"types:{','.join(scope.resource_types)}")
        if scope.geographic_boundary:
            parts.append(f"region:{scope.geographic_boundary}")
        if scope.max_affected_count:
            parts.append(f"max:{scope.max_affected_count}")
        return IntentBinding(
            intent=f"{proposal.decision_type.value}:{proposal.description}",
            target=proposal.target,
            scope_summary="|".join(parts) or "unscoped",
            expected_effect=f"Effect of {proposal.decision_type.value} on {proposal.target}",
            reversibility=proposal.reversibility,
        )

    def _derive_constraints(self, proposal: DecisionProposal, effective_dsal: int = 0) -> dict:
        c: dict = {}
        if not proposal.delegation:
            c["no_delegation"] = True
        if proposal.blast_radius.value in ("significant", "critical"):
            c["require_confirmation"] = True
        if proposal.scope.max_affected_count:
            c["max_affected_count"] = proposal.scope.max_affected_count
        c["effective_dsal"] = effective_dsal
        return c

    def _build_rollback(self, proposal: DecisionProposal) -> RollbackPolicy:
        return RollbackPolicy(
            strategy=f"Rollback {proposal.decision_type.value} on {proposal.target}",
            rollback_window_seconds=3600,
            automated=True,  # rollback is always offered; activation depends on policy
        )

    def _check_prod_reversibility(self, proposal: DecisionProposal) -> "DeniedDecision | None":
        """Deny irreversible ops on production targets when prod_reversibility is enabled (SPEC §8.3)."""
        import re
        ac = self._policy.org_policy.absolute_constraints
        if not ac.prod_reversibility:
            return None
        pattern = ac.prod_target_pattern
        if re.search(pattern, proposal.target, re.IGNORECASE) and not proposal.reversibility:
            return DeniedDecision(
                decision_id=proposal.decision_id,
                reason=(
                    f"OrgPolicy.prod_reversibility is enabled. Irreversible operations on "
                    f"production targets are always denied. Target '{proposal.target}' matches "
                    f"prod pattern '{pattern}'."
                ),
                proposal=proposal,
            )
        return None

    @staticmethod
    def _build_propagated_constraints(posture: UserPosture) -> list[str]:
        """Serialize UserPosture constraints as propagated_constraints strings (SPEC §8.8)."""
        c = posture.constraints
        return [
            f"target_scope:{c.target_scope}",
            f"max_blast_radius:{c.max_blast_radius}",
            f"reversibility_required:{str(c.reversibility_required).lower()}",
            f"minimum_evidence:{c.minimum_evidence}",
        ]

    _KNOWN_CONSTRAINT_KEYS: frozenset = frozenset([
        "target_scope", "max_blast_radius", "reversibility_required", "minimum_evidence",
    ])

    @staticmethod
    def _validate_propagated_constraints(constraints: list[str]) -> list[str]:
        """Return list of constraints with unrecognized vocabulary keys (SPEC §8.8)."""
        unknown = []
        for c in constraints:
            key = c.split(":", 1)[0] if ":" in c else c
            if key not in ShaniEvaluator._KNOWN_CONSTRAINT_KEYS:
                unknown.append(c)
        return unknown

    def _validate_propagated_constraints_via_engine(
        self,
        proposal: DecisionProposal,
        parent_ado: AuthorizedDecisionObject,
    ) -> "PostureRefinementRequest | None":
        """
        Validate propagated_constraints through PostureEngine (SPEC §8.8).

        Returns PostureRefinementRequest if validation fails or is ambiguous,
        None if the proposal satisfies all propagated constraints.
        Unknown vocabulary → PostureRefinementRequest (not DeniedDecision).
        """
        from ..schemas.posture import PostureConstraints, PostureOutcome, UserPosture
        from datetime import datetime, timezone

        props: dict[str, str] = {}
        unknown: list[str] = []

        for c in parent_ado.propagated_constraints:
            key, _, value = c.partition(":") if ":" in c else (c, "", "")
            if key not in self._KNOWN_CONSTRAINT_KEYS:
                unknown.append(c)
            else:
                props[key] = value

        if unknown:
            logger.warning(
                "CROSS-ORG AMBIGUOUS | decision=%s unknown_vocab=%s",
                proposal.decision_id[:8], unknown,
            )
            return PostureRefinementRequest(
                proposal_id=proposal.decision_id,
                principal_id=parent_ado.origin_org or "unknown",
                ambiguity=(
                    f"Incoming propagated_constraints from {parent_ado.origin_org!r} "
                    f"contain unrecognized vocabulary: {unknown}. "
                    "Cannot validate cross-org constraint chain."
                ),
                matched_constraints=[],
                unresolved=unknown,
            )

        try:
            rev_str = props.get("reversibility_required", "false").lower()
            constraints = PostureConstraints(
                target_scope=props.get("target_scope", ".*"),
                max_blast_radius=props.get("max_blast_radius", "critical"),
                reversibility_required=rev_str in ("true", "1", "yes"),
                minimum_evidence=int(props.get("minimum_evidence", "0")),
            )
        except (ValueError, TypeError) as exc:
            return PostureRefinementRequest(
                proposal_id=proposal.decision_id,
                principal_id=parent_ado.origin_org or "unknown",
                ambiguity=(
                    f"Failed to parse propagated_constraints from {parent_ado.origin_org!r}: {exc}"
                ),
                matched_constraints=[],
                unresolved=list(parent_ado.propagated_constraints),
            )

        propagated_posture = UserPosture(
            version="propagated",
            principal_id=parent_ado.origin_org or "unknown",
            signed_at=datetime.now(tz=timezone.utc),
            intent_statement="Cross-org propagated constraints",
            simulation_ref="propagated",
            constraints=constraints,
        )

        engine = PostureEngine(propagated_posture)
        outcome, refinement = engine.evaluate(proposal)

        if outcome == PostureOutcome.PASS:
            return None

        if outcome == PostureOutcome.REJECT:
            logger.warning(
                "CROSS-ORG REJECT | decision=%s origin=%s propagated_constraints=%s",
                proposal.decision_id[:8], parent_ado.origin_org,
                parent_ado.propagated_constraints,
            )
            return PostureRefinementRequest(
                proposal_id=proposal.decision_id,
                principal_id=parent_ado.origin_org or "unknown",
                ambiguity=(
                    f"Proposal rejected by cross-org propagated_constraints "
                    f"from {parent_ado.origin_org!r}. The originating principal's "
                    "posture constraints prohibit this action."
                ),
                matched_constraints=refinement.matched_constraints if refinement else [],
                unresolved=refinement.unresolved if refinement else [],
            )

        # AMBIGUOUS
        return PostureRefinementRequest(
            proposal_id=proposal.decision_id,
            principal_id=parent_ado.origin_org or "unknown",
            ambiguity=(
                f"Cross-org propagated_constraints from {parent_ado.origin_org!r} "
                "could not determine whether this proposal is within scope."
            ),
            matched_constraints=refinement.matched_constraints if refinement else [],
            unresolved=refinement.unresolved if refinement else [],
        )

    def verify_signature_chain(self, ado: "AuthorizedDecisionObject") -> tuple[bool, str]:
        """
        Verify the full ADO signature chain (authority → boundary).

        Returns (True, "OK") if valid, (False, reason) otherwise.
        Falls back to boundary-only verification if no chain is stored.
        """
        from ..crypto.signing import ADOChainVerifier, ADOSignatureChain, ADOSignature
        if ado.signature_chain is None:
            # No chain stored — verify boundary signature only
            ok = self.verify_binding(ado)
            return (True, "OK") if ok else (False, "Boundary signature verification failed.")
        try:
            chain_data = ado.signature_chain
            chain = ADOSignatureChain(
                signatures=[
                    ADOSignature(**s) for s in chain_data.get("signatures", [])
                ]
            )
            payload = self._canonical_payload(ado)
            return ADOChainVerifier.verify(
                payload, chain, expected_roles=["authority", "boundary"]
            )
        except Exception as exc:
            return False, f"Chain verification failed: {exc}"

    @staticmethod
    def _default_keypair(principal_id: str) -> SigningKeypair:
        import hashlib
        import warnings
        env_key = os.environ.get(f"SHANI_{principal_id.upper().replace('-','_')}_KEY")
        if env_key:
            seed = hashlib.sha256(env_key.encode()).digest()
        else:
            warnings.warn(
                f"No signing key for '{principal_id}'. Using insecure default.",
                stacklevel=4,
            )
            seed = hashlib.sha256(f"insecure-default-{principal_id}".encode()).digest()
        return SigningKeypair.from_seed(principal_id, seed)
