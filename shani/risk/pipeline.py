"""
shani/risk/pipeline.py

RiskPipeline — evaluation pipeline integrating the four components.

Evaluation flow:
    DecisionProposal
        ↓
    [1] EvidenceEvaluator   → evidence quality score
        ↓
    [2] RiskAssessor        → RiskScore (aggregate + dimensions)
        ↓
    [3] RuleEngine          → DENY / OVERRIDE / PASS
        ↓
    [4] DecisionSpaceAnalyzer → framing_risk_score
        ↓
    [5] DSALMapper          → effective_dsal
        ↓
    PipelineResult

each component operates independently。
Pipeline calls them in order and aggregates results。

separation of concerns:
    EvidenceEvaluator  → evaluates evidence quality
    RiskAssessor       → evaluates risk across multiple dimensions (no D-SAL knowledge)
    RuleEngine         → overrides with hard rules
    DecisionSpaceAnalyzer → detects framing attacks
    DSALMapper         → converts risk to D-SAL
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schemas.decision import DecisionProposal
from .assessor import RiskAssessor, RiskScore
from .dsal_mapper import DSALMapper, DSALMapping
from .rules import RuleEngine, RuleResult
from .evidence import EvidenceEvaluator, EvidenceEvaluation
from .evidence_fetcher import EvidenceFetcher
from .decision_space import DecisionSpaceAnalyzer, DecisionSpaceAnalysis, Alternative


@dataclass(frozen=True)
class PipelineResult:
    """final output of RiskPipeline。"""

    # ─ results from each component ─
    evidence_eval: EvidenceEvaluation
    risk_score: RiskScore
    rule_result: RuleResult
    decision_space: DecisionSpaceAnalysis
    dsal_mapping: DSALMapping

    # ─ final verdict ─
    effective_dsal: int
    is_hard_denied: bool  # RuleEngine issued a DENY
    deny_reason: str | None  # denial reason when DENY is issued

    def explain(self) -> str:
        lines = [
            "=" * 60,
            "RiskPipeline Result",
            "=" * 60,
            "",
            self.evidence_eval.explain(),
            "",
            self.risk_score.explain(),
            "",
            self.rule_result.explain(),
            "",
            self.decision_space.explain(),
            "",
            self.dsal_mapping.explain(),
            "",
            f"→ effective_dsal = {self.effective_dsal}",
        ]
        if self.is_hard_denied:
            lines.append(f"→ HARD DENIED: {self.deny_reason}")
        return "\n".join(lines)


class RiskPipeline:
    """
    Pipeline that integrates the four risk evaluation components.

    Called by the Evaluator. The Evaluator reads
    effective_dsal and is_hard_denied from PipelineResult.
    """

    def __init__(
        self,
        risk_assessor: RiskAssessor | None = None,
        dsal_mapper: DSALMapper | None = None,
        rule_engine: RuleEngine | None = None,
        evidence_eval: EvidenceEvaluator | None = None,
        space_analyzer: DecisionSpaceAnalyzer | None = None,
        evidence_fetcher: EvidenceFetcher | None = None,
    ):
        self._risk = risk_assessor or RiskAssessor()
        self._mapper = dsal_mapper or DSALMapper()
        self._rules = rule_engine or RuleEngine()
        self._evidence = evidence_eval or EvidenceEvaluator()
        self._space = space_analyzer or DecisionSpaceAnalyzer()
        self._fetcher = evidence_fetcher or EvidenceFetcher()

    def evaluate(
        self,
        proposal: DecisionProposal,
        base_dsal: int,
        alternatives: list[Alternative] | None = None,
    ) -> PipelineResult:
        """
        performs a complete risk evaluation。

        Args:
            proposal:     DecisionProposal to be evaluated
            base_dsal:    base D-SAL from decision_type policy
            alternatives: alternatives considered by the agent (for framing detection)
        """

        # ─ Step 0: Evidence resolution (Pull-based) ───────────────────────
        # Retrieves items with raw_reference set from trusted sources and
        # overwrites agent-provided content (downgrades unresolved items)
        resolved_evidence = self._fetcher.resolve(list(proposal.evidence))

        # ─ Step 1: Evidence evaluation ─────────────────────────────────
        ev_eval = self._evidence.evaluate(resolved_evidence)

        # low evidence quality is reflected in the risk_score
        # RiskAssessor's evidence dimension reads directly from the evidence list
        # propagate additional flags to risk

        # ─ Step 2: Risk assessment (no D-SAL knowledge) ─────────────────────────
        risk_score = self._risk.assess(proposal)

        # integrate evidence quality into the evidence dimension of risk_score
        # (evidence dimension computed by RiskAssessor is adjusted by ev_eval)
        risk_score = self._integrate_evidence_quality(risk_score, ev_eval)

        # ─ Step 3: rule engine ─────────────────────────────────────
        rule_result = self._rules.evaluate(proposal, risk_score)

        # ─ Step 4: Decision Space (framing detection) ──────────────────
        ds_analysis = self._space.analyze(proposal, alternatives)

        # framing_risk is incorporated into the risk_score aggregate
        adjusted_aggregate = min(1.0, risk_score.aggregate + ds_analysis.framing_risk_score * 0.2)
        # simple override (rebuild because frozen dataclass)
        from dataclasses import replace

        risk_score = RiskScore(
            aggregate=round(adjusted_aggregate, 4),
            dimensions=risk_score.dimensions,
            flags={**risk_score.flags, **ds_analysis.flags},
            raw=risk_score.raw,
        )

        # ─ Step 5: D-SAL mapping ───────────────────────────────────────
        mapping = self._mapper.map(risk_score, base_dsal)

        # if OVERRIDE rules exist, take the maximum D-SAL
        effective = mapping.effective_dsal
        if rule_result.override_dsal is not None:
            effective = max(effective, rule_result.override_dsal)

        # ─ final verdict ───────────────────────────────────────────────────
        is_denied = rule_result.is_denied
        deny_reason = rule_result.final_deny.reason if is_denied else None

        return PipelineResult(
            evidence_eval=ev_eval,
            risk_score=risk_score,
            rule_result=rule_result,
            decision_space=ds_analysis,
            dsal_mapping=mapping,
            effective_dsal=effective,
            is_hard_denied=is_denied,
            deny_reason=deny_reason,
        )

    def _integrate_evidence_quality(
        self,
        risk_score: RiskScore,
        ev_eval: EvidenceEvaluation,
    ) -> RiskScore:
        """
        Integrates EvidenceEvaluator results into the evidence dimension of RiskScore.

        Lower ev_eval.quality_score means higher evidence risk.
        Updates the evidence dimension of RiskScore based on ev_eval.
        """
        from .assessor import RiskDimension

        evidence_risk = 1.0 - ev_eval.quality_score
        new_dims = []
        replaced = False
        for dim in risk_score.dimensions:
            if dim.name == "evidence":
                new_dims.append(
                    RiskDimension(
                        name="evidence",
                        score=evidence_risk,
                        weight=dim.weight,
                        explanation=ev_eval.summary,
                    )
                )
                replaced = True
            else:
                new_dims.append(dim)

        if not replaced:
            new_dims.append(
                RiskDimension(
                    name="evidence",
                    score=evidence_risk,
                    weight=0.20,
                    explanation=ev_eval.summary,
                )
            )

        total_weight = sum(d.weight for d in new_dims)
        new_aggregate = sum(d.score * d.weight for d in new_dims) / total_weight

        merged_flags = {**risk_score.flags, **ev_eval.flags}

        return RiskScore(
            aggregate=round(new_aggregate, 4),
            dimensions=new_dims,
            flags=merged_flags,
            raw=risk_score.raw,
        )
