"""
shani/risk/assessor.py

Risk Assessment Layer — operates independently of D-SAL.

Design principles:
    risk_score is a continuous value (0.0–1.0) representing how dangerous the operation is.
    D-SAL is a discrete value (0–4) representing who may approve.

    These answer different questions and must not be conflated.

    The risk_score → D-SAL conversion is performed by DSALMapper (configurable in policy.yaml).
    risk_score itself has no knowledge of D-SAL.

RiskScore composition:
    Each dimension holds an independent score (0.0–1.0)。
    aggregate is the weighted average。weights are configurable in policy.yaml。

    Dimensions:
        blast_radius    scope of impact
        reversibility   rollback feasibility
        environment     target environment (prod > staging > dev)
        evidence        evidence quality and quantity
        intent_clarity  intent clarity (framing attack detection)
        agent_trust     agent trust score (future extension)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schemas.decision import DecisionProposal, BlastRadius


# ---------------------------------------------------------------------------
# RiskScore
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskDimension:
    """A single risk dimension."""

    name: str
    score: float  # 0.0 (low risk) 〜 1.0 (high risk)
    weight: float  # weight for the weighted average
    explanation: str  # explanation of why this score was assigned


@dataclass(frozen=True)
class RiskScore:
    """
    risk assessment result for a proposal。

    aggregate: weighted average score (0.0–1.0)
    dimensions: breakdown by dimension
    flags: boolean flags (used for critical case detection)
    """

    aggregate: float  # final score
    dimensions: list[RiskDimension]
    flags: dict[str, bool] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def explain(self) -> str:
        lines = [f"RiskScore: {self.aggregate:.3f}"]
        for d in self.dimensions:
            bar = "█" * int(d.score * 10) + "░" * (10 - int(d.score * 10))
            lines.append(f"  {d.name:<18} {bar} {d.score:.2f} (w={d.weight:.1f})  {d.explanation}")
        if self.flags:
            lines.append(f"  flags: {self.flags}")
        return "\n".join(lines)

    def has_flag(self, flag: str) -> bool:
        return self.flags.get(flag, False)


# ---------------------------------------------------------------------------
# RiskAssessor
# ---------------------------------------------------------------------------

# environment keywords and their risk coefficients
_ENV_RISK = {
    "prod": 1.0,
    "production": 1.0,
    "live": 1.0,
    "prd": 0.9,
    "staging": 0.5,
    "stage": 0.5,
    "stg": 0.5,
    "dev": 0.1,
    "development": 0.1,
    "local": 0.05,
    "test": 0.1,
}

# BlastRadius → score mapping
_BLAST_SCORE = {
    BlastRadius.ISOLATED: 0.1,
    BlastRadius.LIMITED: 0.3,
    BlastRadius.SIGNIFICANT: 0.7,
    BlastRadius.CRITICAL: 1.0,
}


class RiskAssessor:
    """
    Evaluates risk in a DecisionProposal across multiple dimensions.

    Has no knowledge of D-SAL. D-SAL conversion is performed by DSALMapper.
    """

    def __init__(self, weights: dict[str, float] | None = None):
        # Default weights (overridable in policy.yaml)
        self._weights = weights or {
            "blast_radius": 0.25,
            "reversibility": 0.20,
            "environment": 0.20,
            "evidence": 0.20,
            "intent_clarity": 0.15,
        }

    def assess(self, proposal: DecisionProposal) -> RiskScore:
        dims: list[RiskDimension] = []
        flags: dict[str, bool] = {}

        # ── Dimension 1: blast_radius ──────────────────────────────────
        blast_score = _BLAST_SCORE.get(proposal.blast_radius, 0.5)
        dims.append(
            RiskDimension(
                name="blast_radius",
                score=blast_score,
                weight=self._weights["blast_radius"],
                explanation=f"{proposal.blast_radius.value}",
            )
        )
        if proposal.blast_radius == BlastRadius.CRITICAL:
            flags["critical_blast"] = True

        # ── Dimension 2: reversibility ─────────────────────────────────
        rev_score = 0.0 if proposal.reversibility else 0.9
        dims.append(
            RiskDimension(
                name="reversibility",
                score=rev_score,
                weight=self._weights["reversibility"],
                explanation="reversible" if proposal.reversibility else "IRREVERSIBLE",
            )
        )
        if not proposal.reversibility and blast_score >= 0.7:
            flags["irreversible_high_blast"] = True

        # ── Dimension 3: environment ───────────────────────────────────
        target_lower = proposal.target.lower()
        env_score = 0.1  # default: unknown = low
        env_name = "unknown"
        for kw, risk in _ENV_RISK.items():
            if kw in target_lower:
                if risk > env_score:
                    env_score = risk
                    env_name = kw
        dims.append(
            RiskDimension(
                name="environment",
                score=env_score,
                weight=self._weights["environment"],
                explanation=f"detected: {env_name}" if env_name != "unknown" else "no env keyword",
            )
        )
        if env_score >= 1.0:
            flags["production_target"] = True

        # ── Dimension 4: evidence ──────────────────────────────────────
        ev = proposal.evidence
        if not ev:
            ev_score = 1.0  # no evidence = highest risk
            ev_explanation = "no evidence"
            flags["no_evidence"] = True
        else:
            confidences = [e.confidence for e in ev if e.confidence is not None]
            avg_conf = sum(confidences) / len(confidences) if confidences else 0.5
            source_count = len({e.source for e in ev})

            # composite score of evidence quantity and confidence
            quantity_score = max(0.0, 1.0 - len(ev) * 0.25)  # 0 when 4 or more items
            confidence_score = 1.0 - avg_conf
            diversity_score = max(0.0, 1.0 - source_count * 0.3)  # 0 when 3 or more unique sources

            ev_score = quantity_score * 0.3 + confidence_score * 0.5 + diversity_score * 0.2
            ev_explanation = (
                f"{len(ev)} items, avg_confidence={avg_conf:.2f}, {source_count} source(s)"
            )

            # conflict detection across evidence items
            if avg_conf < 0.4:
                flags["low_confidence_evidence"] = True

        dims.append(
            RiskDimension(
                name="evidence",
                score=ev_score,
                weight=self._weights["evidence"],
                explanation=ev_explanation,
            )
        )

        # ── Dimension 5: intent_clarity ────────────────────────────────
        # detect vagueness and mismatch between description and target
        description = proposal.description.lower()
        vague_words = [
            "some",
            "various",
            "etc",
            "maybe",
            "might",
            "possibly",
            "update",
            "change",
            "modify",
            "fix",
            "adjust",
        ]
        vague_count = sum(1 for w in vague_words if w in description)
        desc_len = len(description)

        if desc_len < 20:
            clarity_score = 0.8  # too short = unclear
        elif vague_count >= 2:
            clarity_score = 0.6  # too many vague words
        elif desc_len > 100:
            clarity_score = 0.1  # detailed description = clear intent
        else:
            clarity_score = 0.3  # neutral

        dims.append(
            RiskDimension(
                name="intent_clarity",
                score=clarity_score,
                weight=self._weights["intent_clarity"],
                explanation=f"desc_len={desc_len}, vague_words={vague_count}",
            )
        )
        if clarity_score >= 0.7:
            flags["unclear_intent"] = True

        # ── Aggregate ─────────────────────────────────────────────────
        total_weight = sum(d.weight for d in dims)
        aggregate = sum(d.score * d.weight for d in dims) / total_weight

        return RiskScore(
            aggregate=round(aggregate, 4),
            dimensions=dims,
            flags=flags,
            raw={
                "proposal_id": proposal.decision_id,
                "decision_type": proposal.decision_type.value,
                "target": proposal.target,
            },
        )
