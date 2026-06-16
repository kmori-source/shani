"""
shani/posture/engine.py

PostureEngine — v0.4 Binding Layer (SPEC §8.4).

Inserted before RiskPipeline in the evaluation pipeline.

Evaluation flow:
    DecisionProposal
         ↓
    PostureEngine
      Layer 1: Static Match (structural field comparison, deterministic, no LLM)
        → REJECT:    proposal field outside UserPosture constraint
        → AMBIGUOUS: structural match insufficient
        → PASS:      all structural constraints satisfied
      Layer 2: Semantic Evaluation
        → REJECT:    proposal is semantically outside UserPosture
        → AMBIGUOUS: PostureEngine cannot determine scope → PostureRefinementRequest
        → PASS:      proceed to RiskPipeline
         ↓ (PASS only)
    RiskPipeline  (unchanged from v0.3)
"""

from __future__ import annotations

import fnmatch
import logging
import re
from typing import TYPE_CHECKING

from ..schemas.decision import BlastRadius, DecisionProposal
from ..schemas.posture import PostureOutcome, PostureRefinementRequest, UserPosture

if TYPE_CHECKING:
    from ..authority.policy import OrgPolicy
    from ..risk.pipeline import RiskPipeline

logger = logging.getLogger("shani.posture.engine")

# Ordered from lowest to highest impact
_BLAST_RADIUS_ORDER: list[BlastRadius] = [
    BlastRadius.ISOLATED,
    BlastRadius.LIMITED,
    BlastRadius.SIGNIFICANT,
    BlastRadius.CRITICAL,
]


class PostureEngine:
    """
    Two-layer posture evaluation engine.

    Layer 1 is deterministic structural comparison (no LLM, no heuristics).
    Layer 2 is semantic evaluation for cases where structural match is insufficient.

    A PostureEngine is instantiated per-evaluation with the active UserPosture.

    Args:
        user_posture: The principal's current UserPosture.
        risk_pipeline: Optional RiskPipeline for Layer 2 semantic evaluation (SPEC §8.4).
        org_policy: Optional OrgPolicy for re-validation at evaluation time (SPEC §8.3).
    """

    def __init__(
        self,
        user_posture: UserPosture,
        risk_pipeline: "RiskPipeline | None" = None,
        org_policy: "OrgPolicy | None" = None,
    ) -> None:
        self._posture = user_posture
        self._risk_pipeline = risk_pipeline
        self._org_policy = org_policy

    def evaluate(
        self, proposal: DecisionProposal
    ) -> tuple[PostureOutcome, PostureRefinementRequest | None]:
        """
        Run two-layer evaluation.

        Returns (outcome, refinement_request).
        refinement_request is non-None only when outcome is AMBIGUOUS.
        REJECT never produces a refinement_request (the violation is deterministic).
        """
        # Re-validate UserPosture against current OrgPolicy (SPEC §8.3).
        # Catches cases where OrgPolicy tightened after the posture was registered.
        if self._org_policy is not None:
            from ..authority.policy import DecisionPolicyProvider

            provider = DecisionPolicyProvider(
                org_policy=self._org_policy,
                allow_unregistered_agents=True,
            )
            ok, reason = provider.validate_user_posture(self._posture)
            if not ok:
                logger.warning(
                    "UserPosture violates current OrgPolicy at evaluation time: %s", reason
                )
                return PostureOutcome.REJECT, None

        outcome1, matched, unresolved = self._layer1(proposal)
        if outcome1 == PostureOutcome.REJECT:
            return PostureOutcome.REJECT, None

        # PASS or AMBIGUOUS from Layer 1 → proceed to Layer 2
        outcome2, matched2, unresolved2 = self._layer2(proposal, matched, unresolved)
        if outcome2 == PostureOutcome.REJECT:
            return PostureOutcome.REJECT, None

        if outcome2 == PostureOutcome.AMBIGUOUS:
            refinement = PostureRefinementRequest(
                proposal_id=proposal.decision_id,
                principal_id=self._posture.principal_id,
                ambiguity=(
                    "PostureEngine could not determine whether the proposal is within scope. "
                    f"Unresolved constraints: {', '.join(unresolved2)}"
                ),
                matched_constraints=matched2,
                unresolved=unresolved2,
                suggested_update=self._suggest_update(unresolved2),
            )
            return PostureOutcome.AMBIGUOUS, refinement

        return PostureOutcome.PASS, None

    # ------------------------------------------------------------------
    # Layer 1: Static structural comparison (SPEC §8.4)
    # Any constraint violation → REJECT (deterministic, no LLM)
    # ------------------------------------------------------------------

    def _layer1(self, proposal: DecisionProposal) -> tuple[PostureOutcome, list[str], list[str]]:
        c = self._posture.constraints
        matched: list[str] = []

        # target_scope: pattern match against proposal.target
        if not self._match_target(proposal.target, c.target_scope):
            return PostureOutcome.REJECT, matched, ["target_scope"]
        matched.append("target_scope")

        # max_blast_radius: enum ordering check
        try:
            proposal_br_idx = _BLAST_RADIUS_ORDER.index(proposal.blast_radius)
            max_br_idx = _BLAST_RADIUS_ORDER.index(BlastRadius(c.max_blast_radius))
        except ValueError:
            # Unknown blast_radius value → AMBIGUOUS (unknown vocabulary)
            return PostureOutcome.AMBIGUOUS, matched, ["max_blast_radius"]
        if proposal_br_idx > max_br_idx:
            return PostureOutcome.REJECT, matched, ["max_blast_radius"]
        matched.append("max_blast_radius")

        # reversibility_required: boolean check
        if c.reversibility_required and not proposal.reversibility:
            return PostureOutcome.REJECT, matched, ["reversibility_required"]
        matched.append("reversibility_required")

        # minimum_evidence: count check
        if len(proposal.evidence) < c.minimum_evidence:
            return PostureOutcome.REJECT, matched, ["minimum_evidence"]
        matched.append("minimum_evidence")

        return PostureOutcome.PASS, matched, []

    # ------------------------------------------------------------------
    # Layer 2: Semantic evaluation (SPEC §8.4)
    # Applied only when Layer 1 yields PASS or AMBIGUOUS.
    # MUST return AMBIGUOUS (not REJECT) when not clearly outside scope.
    # ------------------------------------------------------------------

    def _layer2(
        self,
        proposal: DecisionProposal,
        matched: list[str],
        unresolved: list[str],
    ) -> tuple[PostureOutcome, list[str], list[str]]:
        # If Layer 1 left unresolved constraints, they propagate to AMBIGUOUS here.
        if unresolved:
            return PostureOutcome.AMBIGUOUS, matched, unresolved

        # Semantic evaluation via RiskPipeline (SPEC §8.4).
        # A very high aggregate risk score indicates the proposal is semantically
        # outside the posture's intent scope; a moderate score signals ambiguity.
        if self._risk_pipeline is not None:
            try:
                result = self._risk_pipeline.evaluate(proposal, base_dsal=1, alternatives=None)
                score = result.risk_score.aggregate
                if score >= 0.85:
                    logger.info(
                        "POSTURE LAYER2 REJECT | decision=%s semantic_risk=%.3f",
                        proposal.decision_id[:8],
                        score,
                    )
                    return PostureOutcome.REJECT, matched, ["semantic_risk_exceeded"]
                if score >= 0.6:
                    logger.info(
                        "POSTURE LAYER2 AMBIGUOUS | decision=%s semantic_risk=%.3f",
                        proposal.decision_id[:8],
                        score,
                    )
                    return PostureOutcome.AMBIGUOUS, matched, ["semantic_risk_uncertain"]
            except Exception as exc:
                logger.warning("POSTURE LAYER2 pipeline error — defaulting to AMBIGUOUS | %s", exc)
                return PostureOutcome.AMBIGUOUS, matched, ["semantic_evaluation_failed"]

        return PostureOutcome.PASS, matched, []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match_target(target: str, pattern: str) -> bool:
        """Match target against a regex or glob pattern."""
        try:
            return bool(re.match(pattern, target))
        except re.error:
            return fnmatch.fnmatch(target, pattern)

    @staticmethod
    def _suggest_update(unresolved: list[str]) -> str | None:
        hints = {
            "target_scope": "Broaden target_scope pattern to include this target.",
            "max_blast_radius": "Increase max_blast_radius if this blast level is acceptable.",
            "reversibility_required": "Set reversibility_required: false if irreversible ops are acceptable.",
            "minimum_evidence": "Lower minimum_evidence or add evidence items to the proposal.",
        }
        suggestions = [hints[c] for c in unresolved if c in hints]
        return " ".join(suggestions) if suggestions else None
