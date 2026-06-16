"""
shani/authority/dsal_calculator.py

D-SAL Calculator — Shani computes the effective D-SAL from proposal context。

Design principles:
    Agents declare what they want to do, to what target, and why.
    Shani determines the required oversight level.

    requested_dsal has been removed from DecisionProposal.
    When agents could declare it, they could reduce their own oversight level.

Calculation logic:
    base    = per-decision_type base value from policy.yaml
    adjusted = base + Σ modifiers(proposal context)
    effective = min(adjusted, 4)

Modifier list:
    blast_radius
        SIGNIFICANT  → +1   (wide-area impact)
        CRITICAL     → +2   (system-wide impact)

    reversibility
        False        → +1   (irreversible = high risk)

    target (environment penalty)
        prod/production/live/prd present in target → +1

    evidence
        empty (none)   → +1   (no evidence available)
        avg confidence < 0.6 → +1   (low-confidence evidence)

    delegation
        True             → +1   (spawns sub-agents = propagation risk)

    confidence
        < 0.5            → +1   (agent has low confidence)
"""

from __future__ import annotations

from dataclasses import dataclass

from ..schemas.decision import DecisionProposal, BlastRadius


@dataclass(frozen=True)
class DSALCalculation:
    """calculation result and breakdown。"""

    effective: int  # final effective D-SAL
    base: int  # base value from policy
    modifiers: list[str]  # list of explanations for applied modifiers
    total_adjustment: int  # total adjustment from base

    def explain(self) -> str:
        lines = [
            "D-SAL calculation:",
            f"  base ({self.base}) from decision_type policy",
        ]
        for m in self.modifiers:
            lines.append(f"  {m}")
        lines.append(f"  → effective D-SAL = {self.effective}")
        return "\n".join(lines)


class DSALCalculator:
    """
    DecisionProposal computes the effective D-SAL from proposal context。

    Agents do not declare their own D-SAL。
    this calculator determines it from policy + context。

    The definition of "production environment" is not hardcoded。
    injected from policy.yaml environment_rules。
    """

    _DEFAULT_PROD_KEYWORDS = frozenset(["prod", "production", "live", "prd", "main", "master"])

    def __init__(self, environment_rules: "dict | None" = None):
        """
        Args:
            environment_rules: environment_rules section of policy.yaml。
        """
        if environment_rules:
            self._prod_keywords = frozenset(
                kw.lower() for kw in environment_rules.get("high_risk_keywords", [])
            )
        else:
            self._prod_keywords = self._DEFAULT_PROD_KEYWORDS

    def calculate(
        self,
        proposal: DecisionProposal,
        base_dsal: int,
    ) -> DSALCalculation:
        """
        Computes effective D-SAL from base_dsal (from policy) + context modifiers.

        Args:
            proposal:   DecisionProposal (source of context)
            base_dsal:  base value obtained from decision_type policy
        """
        adjustment = 0
        modifiers: list[str] = []

        # ── Modifier 1: blast_radius ──────────────────────────────────────
        if proposal.blast_radius == BlastRadius.SIGNIFICANT:
            adjustment += 1
            modifiers.append("+1 (blast_radius=significant: wide-area impact)")
        elif proposal.blast_radius == BlastRadius.CRITICAL:
            adjustment += 2
            modifiers.append("+2 (blast_radius=critical: system-wide impact)")

        # ── Modifier 2: reversibility ─────────────────────────────────────
        if not proposal.reversibility:
            adjustment += 1
            modifiers.append("+1 (reversibility=False: irreversible)")

        # ── Modifier 3: target environment penalty ────────────────────────────
        target_lower = proposal.target.lower()
        if any(kw in target_lower for kw in self._prod_keywords):
            adjustment += 1
            modifiers.append(f"+1 (target='{proposal.target}': production environment)")

        # ── Modifier 4: evidence ──────────────────────────────────────────
        if not proposal.evidence:
            adjustment += 1
            modifiers.append("+1 (evidence=empty: no evidence)")
        else:
            confidences = [e.confidence for e in proposal.evidence if e.confidence is not None]
            if confidences:
                avg_confidence = sum(confidences) / len(confidences)
                if avg_confidence < 0.6:
                    adjustment += 1
                    modifiers.append(
                        f"+1 (evidence avg_confidence={avg_confidence:.2f}: low-confidence evidence)"
                    )

        # ── Modifier 5: delegation ────────────────────────────────────────
        if proposal.delegation:
            adjustment += 1
            modifiers.append("+1 (delegation=True: spawns sub-agents)")

        # ── Modifier 6: agent confidence ─────────────────────────────────
        if proposal.confidence < 0.5:
            adjustment += 1
            modifiers.append(f"+1 (confidence={proposal.confidence:.2f}: agent has low confidence)")

        effective = min(base_dsal + adjustment, 4)

        return DSALCalculation(
            effective=effective,
            base=base_dsal,
            modifiers=modifiers,
            total_adjustment=adjustment,
        )
