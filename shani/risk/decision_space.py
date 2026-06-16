"""
shani/risk/decision_space.py

DecisionSpace — framing attack countermeasure。

Problem:
    An agent might write description="minor config update"
    while actually making a significant change (framing attack).

    There is also no mechanism to verify whether the least-privileged option was chosen.
    Example: choosing run_command when read_file would suffice,
             or choosing significant blast_radius when limited would do.

Solution:
    DecisionSpace: Agent declares alternatives that were considered but not chosen。

    Agents declare alternatives they considered but did not choose:
        alternatives = [
            Alternative(
                description="confirm via read-only monitoring",
                decision_type=DecisionType.DATA_ACCESS,
                blast_radius=BlastRadius.ISOLATED,
                reason_rejected="real-time remediation is required; read-only monitoring is insufficient",
            ),
        ]

    DecisionSpaceAnalyzer evaluates this:
        - no alternatives declared → framing suspicion (+risk)
        - lower-risk alternatives rejected → verify the reason
        - thin rejection reason → risk_score UP
        - choosing a clearly higher-risk option than declared alternatives → DENY
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schemas.decision import DecisionProposal, DecisionType, BlastRadius


@dataclass
class Alternative:
    """
    Alternative considered by the agent but not chosen。

    By declaring this, the agent:
        1. demonstrates compliance with the principle of least privilege
        2. allows Shani to verify the appropriateness of the choice
        3. creates an audit trail explaining why this option was chosen
    """

    description: str
    decision_type: str  # DecisionType value
    blast_radius: str  # BlastRadius value
    reason_rejected: str  # reason for rejection

    def risk_level(self) -> int:
        """relative risk level of this alternative (0=lowest, 3=highest)。"""
        blast_map = {"isolated": 0, "limited": 1, "significant": 2, "critical": 3}
        return blast_map.get(self.blast_radius, 1)


@dataclass(frozen=True)
class DecisionSpaceAnalysis:
    """analysis result for the DecisionSpace。"""

    alternatives_provided: bool
    framing_risk_score: float  # 0.0〜1.0、higher value indicates stronger framing suspicion
    flags: dict[str, bool]
    insights: list[str]  # analysis insights

    def explain(self) -> str:
        lines = [
            "DecisionSpaceAnalysis:",
            f"  alternatives_provided: {self.alternatives_provided}",
            f"  framing_risk_score:    {self.framing_risk_score:.3f}",
        ]
        for insight in self.insights:
            lines.append(f"  → {insight}")
        if self.flags:
            lines.append(f"  flags: {self.flags}")
        return "\n".join(lines)


class DecisionSpaceAnalyzer:
    """
    Analyzes the agent's decision space to detect framing attacks。
    """

    # blast_radius ordering
    _BLAST_ORDER = {
        BlastRadius.ISOLATED: 0,
        BlastRadius.LIMITED: 1,
        BlastRadius.SIGNIFICANT: 2,
        BlastRadius.CRITICAL: 3,
    }

    def analyze(
        self,
        proposal: DecisionProposal,
        alternatives: list[Alternative] | None = None,
    ) -> DecisionSpaceAnalysis:
        flags: dict[str, bool] = {}
        insights: list[str] = []
        framing_risk = 0.0

        if not alternatives:
            # no alternatives declared = framing suspicion
            framing_risk += 0.3
            flags["no_alternatives_provided"] = True
            insights.append(
                "No alternatives were declared."
                "Cannot verify compliance with the principle of least privilege."
            )

            # high-risk operation without alternatives is especially suspicious
            if proposal.blast_radius in (BlastRadius.SIGNIFICANT, BlastRadius.CRITICAL):
                framing_risk += 0.2
                insights.append(
                    f"For a blast_radius={proposal.blast_radius.value} operation, "
                    "no alternatives were considered."
                )

            return DecisionSpaceAnalysis(
                alternatives_provided=False,
                framing_risk_score=min(framing_risk, 1.0),
                flags=flags,
                insights=insights,
            )

        # analysis when alternatives are provided
        proposed_blast = self._BLAST_ORDER.get(proposal.blast_radius, 1)

        # check if lower-risk alternatives exist
        lower_risk_alts = [a for a in alternatives if a.risk_level() < proposed_blast]

        if lower_risk_alts:
            for alt in lower_risk_alts:
                if not alt.reason_rejected.strip():
                    # lower-risk alternative rejected without a reason
                    framing_risk += 0.4
                    flags["unexplained_risk_escalation"] = True
                    insights.append(
                        f"Lower-risk alternative '{alt.description}' was rejected without explanation."
                    )
                elif len(alt.reason_rejected) < 20:
                    # rejection reason is too short
                    framing_risk += 0.2
                    flags["thin_rejection_reason"] = True
                    insights.append(
                        f"Rejection reason for '{alt.description}' is too short: '{alt.reason_rejected}'"
                    )
                else:
                    insights.append(
                        f"Lower-risk alternative '{alt.description}' rejected: '{alt.reason_rejected}'"
                    )
        else:
            # no lower-risk alternatives exist = appropriate choice
            framing_risk -= 0.1
            insights.append("No lower-risk alternatives exist (appropriate choice).")

        # comparison with alternatives of the same decision_type
        same_type_alts = [
            a for a in alternatives if a.decision_type == proposal.decision_type.value
        ]
        if same_type_alts:
            insights.append(
                f"{len(same_type_alts)} alternative(s) of the same type were considered"
            )

        framing_risk = max(0.0, min(framing_risk, 1.0))

        return DecisionSpaceAnalysis(
            alternatives_provided=True,
            framing_risk_score=framing_risk,
            flags=flags,
            insights=insights,
        )
