"""
policy_engine.py - Declarative blast_radius policy engine for Shani.

Problem this solves
--------------------
Every Shani integration so far (the pip-audit D-SAL2 mapping, the oss-crs
patch-builder diff heuristic, and whatever comes next) independently
reimplemented the same kind of logic: "look at some evidence, decide how
risky this is, then tell Shani." That duplication is also a security smell -
each integration was the judge of its own risk, and Shani simply trusted the
self-reported `blast_radius` field in the DecisionProposal.

This module gives Shani an independent, declarative, centrally-reviewable
way to compute blast_radius from structured evidence, decision_type, and the
proposing agent's identity. Integrations stop being judges of their own
risk; they just report facts (`evidence[].metadata`), and the *policy*
(authored by whoever runs this Shani deployment) decides the consequence.

Security principle: callers can only escalate, never de-escalate
-------------------------------------------------------------------
A proposal's own `blast_radius` field, if present, is advisory only. The
EFFECTIVE blast_radius used for authorization should be:

    effective = max_severity(policy_engine.evaluate(proposal).blast_radius,
                              proposal.get("blast_radius"))

i.e. a caller may ask Shani to treat its own request as MORE dangerous than
policy would otherwise compute (self-escalation - always fine, an agent that
flags itself as risky should never be punished for that), but it can never
talk Shani into treating something as LESS dangerous than policy says. See
README.md for the full rationale and a migration note for existing
integrations.

Existing-table compatibility note
----------------------------------
shani-governance/SKILL.md's Decision Types table already maps `remediation`
to two different blast_radius values depending on the specific action ("Run
commands" -> significant, "Delete files" -> critical). That is, decision_type
alone was never a complete classifier - this engine makes that fact explicit
via rules instead of leaving it implicit in caller behavior.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# NOTE: PyYAML is intentionally NOT imported at module level. Shani's core
# (`pip install -e .` with no extras) must remain zero-dependency (stdlib
# only) - see 00b_repo_branch_cicd_guide.md section 3.1, "zero-dependency
# confirmation step". `yaml` is only needed by `PolicyEngine.from_yaml()`,
# so the import is deferred into that method. Constructing a PolicyEngine
# directly from a dict (as the tests do) never touches PyYAML at all.

# Ordinal severity, matching the blast_radius enum in shani-governance/SKILL.md.
_SEVERITY_ORDER = {"isolated": 0, "limited": 1, "significant": 2, "critical": 3}


def _severity_rank(value: str) -> int:
    try:
        return _SEVERITY_ORDER[value]
    except KeyError as exc:
        raise ValueError(f"unknown blast_radius value: {value!r}") from exc


def max_severity(*values: Optional[str]) -> str:
    """Return the most severe of the given blast_radius values, ignoring None/empty."""
    ranked = [(v, _severity_rank(v)) for v in values if v]
    if not ranked:
        return "isolated"
    return max(ranked, key=lambda pair: pair[1])[0]


@dataclass
class RuleMatch:
    rule_id: str
    blast_radius: str
    reason: Optional[str] = None


@dataclass
class PolicyResult:
    blast_radius: str
    matched_rules: list[RuleMatch] = field(default_factory=list)
    default_used: bool = False

    def effective(self, caller_supplied_blast_radius: Optional[str]) -> str:
        """Combine the policy's verdict with the caller's own claim.

        The caller may only escalate (see module docstring); it can never
        talk the policy down to something less severe.
        """
        return max_severity(self.blast_radius, caller_supplied_blast_radius)


def _merge_evidence_metadata(proposal: dict[str, Any]) -> dict[str, Any]:
    """Flatten `metadata` dicts across all evidence items into one dict.

    Later evidence items win on key collisions. Evidence items or metadata
    fields are optional; integrations that don't supply structured metadata
    simply won't match metadata-based rules and fall through to defaults -
    this keeps the engine backward-compatible with existing callers.
    """
    merged: dict[str, Any] = {}
    for item in proposal.get("evidence", []) or []:
        merged.update(item.get("metadata", {}) or {})
    return merged


def _matches_numeric(condition: dict[str, Any], actual: Any) -> bool:
    if actual is None:
        return False
    try:
        actual_num = float(actual)
    except (TypeError, ValueError):
        return False
    ops = {
        "gt": lambda a, b: a > b,
        "gte": lambda a, b: a >= b,
        "lt": lambda a, b: a < b,
        "lte": lambda a, b: a <= b,
    }
    return all(ops[op](actual_num, float(bound)) for op, bound in condition.items() if op in ops)


def _matches_metadata_field(condition: Any, actual: Any) -> bool:
    """A single metadata match condition against a single actual value.

    Supported condition shapes:
      - scalar              -> equality
      - list                -> membership (actual in list)
      - {gt/gte/lt/lte: N}  -> numeric comparison
    """
    if isinstance(condition, dict) and any(k in condition for k in ("gt", "gte", "lt", "lte")):
        return _matches_numeric(condition, actual)
    if isinstance(condition, list):
        return actual in condition
    return actual == condition


def _matches_any_glob(patterns: list[str], values: Any) -> bool:
    """True if any string in `values` (a list) matches any glob in `patterns`."""
    if not isinstance(values, (list, tuple)):
        return False
    return any(fnmatch.fnmatch(str(v), pattern) for v in values for pattern in patterns)


def _rule_matches(rule: dict[str, Any], proposal: dict[str, Any], metadata: dict[str, Any]) -> bool:
    match = rule.get("match", {})

    if "decision_type" in match and proposal.get("decision_type") != match["decision_type"]:
        return False

    if "proposed_by_prefix" in match:
        if not proposal.get("proposed_by", "").startswith(match["proposed_by_prefix"]):
            return False

    if "target_prefix" in match:
        if not proposal.get("target", "").startswith(match["target_prefix"]):
            return False

    for key, condition in match.get("metadata", {}).items():
        if key.endswith("_any_glob"):
            field_name = key[: -len("_any_glob")]
            if not _matches_any_glob(condition, metadata.get(field_name)):
                return False
        else:
            if not _matches_metadata_field(condition, metadata.get(key)):
                return False

    return True


class PolicyEngine:
    """Evaluates a DecisionProposal against a declarative rule set.

    Usage:
        engine = PolicyEngine.from_yaml("blast_radius_policy/default.yaml")
        result = engine.evaluate(proposal)
        effective_blast_radius = result.effective(proposal.get("blast_radius"))
    """

    def __init__(self, policy: dict[str, Any]):
        self._defaults: dict[str, str] = policy.get("defaults", {})
        self._rules: list[dict[str, Any]] = policy.get("rules", [])
        self._validate()

    def _validate(self) -> None:
        for value in self._defaults.values():
            _severity_rank(value)  # raises if invalid
        seen_ids: set[str] = set()
        for rule in self._rules:
            if "id" not in rule:
                raise ValueError(f"rule missing required 'id' field: {rule}")
            if rule["id"] in seen_ids:
                raise ValueError(f"duplicate rule id: {rule['id']}")
            seen_ids.add(rule["id"])
            if "blast_radius" not in rule:
                raise ValueError(f"rule {rule['id']!r} missing required 'blast_radius' field")
            _severity_rank(rule["blast_radius"])  # raises if invalid

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        import yaml  # deferred import - see module-level NOTE above

        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    def evaluate(self, proposal: dict[str, Any]) -> PolicyResult:
        metadata = _merge_evidence_metadata(proposal)
        matched: list[RuleMatch] = []

        for rule in self._rules:
            if _rule_matches(rule, proposal, metadata):
                matched.append(
                    RuleMatch(
                        rule_id=rule["id"],
                        blast_radius=rule["blast_radius"],
                        reason=rule.get("description"),
                    )
                )

        if matched:
            blast_radius = max_severity(*(m.blast_radius for m in matched))
            return PolicyResult(blast_radius=blast_radius, matched_rules=matched, default_used=False)

        decision_type = proposal.get("decision_type")
        default_blast_radius = self._defaults.get(decision_type, "significant")
        return PolicyResult(blast_radius=default_blast_radius, matched_rules=[], default_used=True)
