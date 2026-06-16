"""
shani/risk/dsal_mapper.py

DSALMapper — converts risk_score to D-SAL。

Design:
    The risk_score → D-SAL conversion is a pure policy decision。
    thresholds such as "risk ≥ 0.7 requires D-SAL 3" are defined by humans。

    Conversion logic:
        base_dsal (from decision_type policy) as the floor while
        raising the required D-SAL based on risk_score。

    effective_dsal = max(base_dsal, risk_based_dsal)

    risk_based_dsal is determined by the risk_score threshold table (configurable in policy.yaml):
        risk_score < 0.30 → D-SAL 1 (autonomous)
        risk_score < 0.50 → D-SAL 2 (SecOps review)
        risk_score < 0.70 → D-SAL 3 (Policy approval)
        risk_score >= 0.70 → D-SAL 4 (Board approval)
"""

from __future__ import annotations

from dataclasses import dataclass

from .assessor import RiskScore


@dataclass(frozen=True)
class DSALMapping:
    """D-SAL mapping result and breakdown。"""

    effective_dsal: int
    base_dsal: int  # from decision_type policy
    risk_based_dsal: int  # derived from risk_score
    risk_score: float
    risk_score_detail: str  # summary for explain()
    binding: str  # which bound applied ("base" or "risk") ("base" | "risk")

    def explain(self) -> str:
        return (
            f"DSALMapping:\n"
            f"  base_dsal       = {self.base_dsal}  (from decision_type policy)\n"
            f"  risk_score      = {self.risk_score:.3f}\n"
            f"  risk_based_dsal = {self.risk_based_dsal}  (from risk thresholds)\n"
            f"  effective_dsal  = {self.effective_dsal}  (max of above, binding={self.binding})\n"
            f"  {self.risk_score_detail}"
        )


# Default threshold table (overridable in policy.yaml)
DEFAULT_THRESHOLDS: list[tuple[float, int]] = [
    (0.30, 1),  # risk < 0.30 → D-SAL 1
    (0.50, 2),  # risk < 0.50 → D-SAL 2
    (0.70, 3),  # risk < 0.70 → D-SAL 3
    (1.01, 4),  # risk >= 0.70 → D-SAL 4
]


class DSALMapper:
    """
    Converts risk_score to effective_dsal.

    Policy administrators can adjust the threshold table to
    allows defining governance aligned with organizational risk tolerance。
    """

    def __init__(self, thresholds: list[tuple[float, int]] | None = None):
        # [(risk_threshold, required_dsal), ...] sorted ascending
        self._thresholds = sorted(thresholds or DEFAULT_THRESHOLDS, key=lambda x: x[0])

    def map(
        self,
        risk_score: RiskScore,
        base_dsal: int,
    ) -> DSALMapping:
        """
        Computes effective_dsal from risk_score and base_dsal.

        effective = max(base_dsal, risk_based_dsal)
        → base_dsal guarantees a floor (the policy-defined minimum)
        → risk_based_dsal raises the floor when risk is high
        """
        risk_based = self._risk_to_dsal(risk_score.aggregate)
        effective = max(base_dsal, risk_based)
        binding = "base" if base_dsal >= risk_based else "risk"

        # risk_score summary (highest-scoring dimension)
        if risk_score.dimensions:
            top = max(risk_score.dimensions, key=lambda d: d.score * d.weight)
            detail = f"top risk factor: {top.name}={top.score:.2f} ({top.explanation})"
        else:
            detail = "no dimensions"

        return DSALMapping(
            effective_dsal=effective,
            base_dsal=base_dsal,
            risk_based_dsal=risk_based,
            risk_score=risk_score.aggregate,
            risk_score_detail=detail,
            binding=binding,
        )

    def _risk_to_dsal(self, score: float) -> int:
        for threshold, dsal in self._thresholds:
            if score < threshold:
                return dsal
        return 4  # fallback
