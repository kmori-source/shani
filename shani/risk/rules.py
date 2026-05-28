"""
shani/risk/rules.py

RuleEngine — hard rules that override the risk score。

Design:
    risk_score is a continuous evaluation driven by modifier accumulation.
    However, "never allow" cases cannot be expressed as continuous values.

    Examples:
        - network_action on prod-db requires at least 3 evidence items or DENY
        - blast_radius=CRITICAL + reversibility=False always requires D-SAL 4
        - policy_update never falls below D-SAL 4 (hardcoded floor)

    RuleEngine expresses these invariants.
    Rule matching is evaluated before risk_score calculation。

RuleOutcome types:
    PASS      → no rule matched; return to normal flow
    OVERRIDE  → force D-SAL to specified value (can raise or lower)
    DENY      → immediate rejection (with reason)
    REQUIRE   → demand additional conditions (e.g., N evidence items required)

Example rule definitions (configurable via policy.yaml):

    rules:
      - name: prod_network_deny_without_evidence
        condition:
          target_contains: ["prod", "live"]
          decision_type: network_action
          evidence_count_lt: 3
        outcome: DENY
        reason: "Production network operations require at least 3 evidence items."

      - name: critical_irreversible_floor
        condition:
          blast_radius: critical
          reversibility: false
        outcome: OVERRIDE
        dsal: 4
        reason: "CRITICAL blast_radius + irreversible operation always requires D-SAL 4."

      - name: policy_update_hardcoded_floor
        condition:
          decision_type: policy_update
        outcome: OVERRIDE
        dsal: 4
        reason: "policy_update always requires D-SAL 4 (immutable)."
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..schemas.decision import DecisionProposal, BlastRadius, DecisionType
from .assessor import RiskScore


class RuleOutcomeType(str, Enum):
    PASS      = "pass"
    OVERRIDE  = "override"
    DENY      = "deny"
    REQUIRE   = "require"


@dataclass(frozen=True)
class RuleOutcome:
    outcome:    RuleOutcomeType
    rule_name:  str
    reason:     str
    dsal:       int | None = None        # used when outcome is OVERRIDE
    requirement: str | None = None      # used when outcome is REQUIRE

    @property
    def is_deny(self) -> bool:
        return self.outcome == RuleOutcomeType.DENY

    @property
    def is_override(self) -> bool:
        return self.outcome == RuleOutcomeType.OVERRIDE

    @property
    def is_pass(self) -> bool:
        return self.outcome == RuleOutcomeType.PASS


@dataclass(frozen=True)
class RuleResult:
    """Evaluation result from the RuleEngine."""
    outcomes:       list[RuleOutcome]
    final_deny:     RuleOutcome | None       # first DENY if any
    final_override: RuleOutcome | None       # highest D-SAL from OVERRIDE rules
    applied_rules:  list[str]

    @property
    def is_denied(self) -> bool:
        return self.final_deny is not None

    @property
    def override_dsal(self) -> int | None:
        return self.final_override.dsal if self.final_override else None

    def explain(self) -> str:
        if not self.outcomes:
            return "RuleEngine: no rules matched (PASS)"
        lines = ["RuleEngine:"]
        for o in self.outcomes:
            lines.append(f"  [{o.outcome.value.upper()}] {o.rule_name}: {o.reason}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Built-in rules (always active)
# ---------------------------------------------------------------------------

class Rule:
    """Base class for rules."""
    name: str = "unnamed"

    def evaluate(
        self,
        proposal: DecisionProposal,
        risk_score: RiskScore,
    ) -> RuleOutcome | None:
        """Returning None means the rule did not match (PASS)."""
        raise NotImplementedError


class PolicyUpdateFloorRule(Rule):
    """policy_update always requires D-SAL 4. Immutable."""
    name = "policy_update_hardcoded_floor"

    def evaluate(self, proposal, risk_score):
        if proposal.decision_type == DecisionType.POLICY_UPDATE:
            return RuleOutcome(
                outcome=RuleOutcomeType.OVERRIDE,
                rule_name=self.name,
                reason="policy_update always requires D-SAL 4 (governance itself requires maximum approval).",

                dsal=4,
            )
        return None


class CriticalIrreversibleRule(Rule):
    """CRITICAL blast_radius + irreversible operation always requires D-SAL 4."""
    name = "critical_irreversible_floor"

    def evaluate(self, proposal, risk_score):
        if (proposal.blast_radius == BlastRadius.CRITICAL
                and not proposal.reversibility):
            return RuleOutcome(
                outcome=RuleOutcomeType.OVERRIDE,
                rule_name=self.name,
                reason="CRITICAL blast_radius + irreversible operation always requires D-SAL 4.",
                dsal=4,
            )
        return None


class ProdNetworkNoEvidenceRule(Rule):
    """DENY if production network operation has fewer than 2 evidence items."""
    name = "prod_network_insufficient_evidence"

    def evaluate(self, proposal, risk_score):
        if proposal.decision_type != DecisionType.NETWORK_ACTION:
            return None
        target_lower = proposal.target.lower()
        is_prod = any(kw in target_lower for kw in ["prod", "live", "prd", "production"])
        if not is_prod:
            return None
        if len(proposal.evidence) < 2:
            return RuleOutcome(
                outcome=RuleOutcomeType.DENY,
                rule_name=self.name,
                reason=(
                    f"Production network operations require at least 2 evidence items "
                    f"(current count: {len(proposal.evidence)})"
                ),
            )
        return None


class NoEvidenceCriticalDenyRule(Rule):
    """DENY if blast_radius is CRITICAL and evidence is empty."""
    name = "no_evidence_critical_deny"

    def evaluate(self, proposal, risk_score):
        if (not proposal.evidence
                and proposal.blast_radius == BlastRadius.CRITICAL):
            return RuleOutcome(
                outcome=RuleOutcomeType.DENY,
                rule_name=self.name,
                reason="CRITICAL blast_radius operations require evidence",
            )
        return None


class LowConfidenceHighRiskRule(Rule):
    """DENY if risk_score is high and agent confidence is low."""
    name = "low_confidence_high_risk"

    def evaluate(self, proposal, risk_score):
        if risk_score.aggregate >= 0.8 and proposal.confidence < 0.4:
            return RuleOutcome(
                outcome=RuleOutcomeType.DENY,
                rule_name=self.name,
                reason=(
                    f"risk_score={risk_score.aggregate:.2f} is high, yet "
                    f"agent confidence={proposal.confidence:.2f} is too low"
                ),
            )
        return None


# ---------------------------------------------------------------------------
# RuleEngine
# ---------------------------------------------------------------------------

# Built-in rules (active by default)
DEFAULT_RULES: list[Rule] = [
    PolicyUpdateFloorRule(),
    CriticalIrreversibleRule(),
    ProdNetworkNoEvidenceRule(),
    NoEvidenceCriticalDenyRule(),
    LowConfidenceHighRiskRule(),
]


class RuleEngine:
    """
    Evaluates rules in order and returns DENY / OVERRIDE / PASS。

    Evaluation order:
        1. DENY rules take priority (a single DENY causes immediate rejection)
        2. OVERRIDE rules (if multiple, the highest D-SAL wins)
        3. no match → PASS
    """

    def __init__(self, extra_rules: list[Rule] | None = None):
        self._rules = list(DEFAULT_RULES) + (extra_rules or [])

    def evaluate(
        self,
        proposal: DecisionProposal,
        risk_score: RiskScore,
    ) -> RuleResult:
        outcomes: list[RuleOutcome] = []
        applied: list[str] = []

        for rule in self._rules:
            outcome = rule.evaluate(proposal, risk_score)
            if outcome is not None:
                outcomes.append(outcome)
                applied.append(rule.name)

        # return the first DENY if any
        denies = [o for o in outcomes if o.is_deny]
        final_deny = denies[0] if denies else None

        # use the highest D-SAL among OVERRIDE outcomes
        overrides = [o for o in outcomes if o.is_override and o.dsal is not None]
        final_override = (
            max(overrides, key=lambda o: o.dsal)
            if overrides else None
        )

        return RuleResult(
            outcomes=outcomes,
            final_deny=final_deny,
            final_override=final_override,
            applied_rules=applied,
        )

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)
