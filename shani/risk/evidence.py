"""
shani/risk/evidence.py

Evidence Evaluator — epistemic security layer.

Problem:
    evidence=[EvidenceItem(source="monitor", content="CPU high")]
    is self-reported. Agents can fabricate evidence.

    Also, a chain of Agent A observes → B interprets → C proposes
    degrades evidence quality in ways that cannot be tracked.

Solution:
    1. SourceTrust: source trust classification
       SYSTEM_SENSOR  → highest trust (direct sensor data)
       VERIFIED_TOOL  → high trust (output of verified tools)
       AGENT_DERIVED  → medium trust (interpretation by another agent)
       SELF_REPORTED  → low trust (self-report by the proposing agent)
       UNKNOWN        → unverified (unclassified)

    2. EvidenceChain: track evidence propagation chain
       confidence degrades at each step: observation → interpretation → proposal

    3. ConflictDetector: conflicting evidence detection
       conflicting evidence about the same fact is reflected in risk_score

    4. EvidenceEvaluator: aggregates the above to return an evidence quality score
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from ..schemas.decision import EvidenceItem


# ---------------------------------------------------------------------------
# Source trust levels
# ---------------------------------------------------------------------------

class SourceTrust(str, Enum):
    SYSTEM_SENSOR = "system_sensor"    # direct sensors, EDR, SIEM
    VERIFIED_TOOL = "verified_tool"    # output of verified tools
    AGENT_DERIVED = "agent_derived"    # interpretation by another agent
    SELF_REPORTED = "self_reported"    # self-report by the proposing agent
    UNKNOWN       = "unknown"          # unclassified

# source keyword → trust level mapping
# IMPORTANT: longer / more-specific prefixes must appear BEFORE shorter ones
# because classify_source() returns on the first substring match.
_SOURCE_TRUST_MAP: dict[str, SourceTrust] = {
    # unverified reference (must come first — prefix contains other keywords like "edr")
    "unverified_reference": SourceTrust.SELF_REPORTED,
    # system sensors
    "edr": SourceTrust.SYSTEM_SENSOR,
    "siem": SourceTrust.SYSTEM_SENSOR,
    "monitor": SourceTrust.SYSTEM_SENSOR,
    "sensor": SourceTrust.SYSTEM_SENSOR,
    "prometheus": SourceTrust.SYSTEM_SENSOR,
    "datadog": SourceTrust.SYSTEM_SENSOR,
    "cloudwatch": SourceTrust.SYSTEM_SENSOR,
    # verified tools
    "nmap": SourceTrust.VERIFIED_TOOL,
    "scanner": SourceTrust.VERIFIED_TOOL,
    "audit": SourceTrust.VERIFIED_TOOL,
    "log": SourceTrust.VERIFIED_TOOL,
    # agent derived
    "agent": SourceTrust.AGENT_DERIVED,
    "brain": SourceTrust.AGENT_DERIVED,
    "llm": SourceTrust.AGENT_DERIVED,
    "openclaw": SourceTrust.AGENT_DERIVED,
    "langgraph": SourceTrust.AGENT_DERIVED,
    # self reported
    "self": SourceTrust.SELF_REPORTED,
    "agent-observation": SourceTrust.SELF_REPORTED,
    "my": SourceTrust.SELF_REPORTED,
}

_TRUST_MULTIPLIER: dict[SourceTrust, float] = {
    SourceTrust.SYSTEM_SENSOR: 1.0,
    SourceTrust.VERIFIED_TOOL: 0.85,
    SourceTrust.AGENT_DERIVED: 0.60,
    SourceTrust.SELF_REPORTED: 0.35,
    SourceTrust.UNKNOWN:       0.50,
}

# Evidence quality scoring constants — extracted for auditability and testability.
_CONFLICT_CONFIDENCE_THRESHOLD = 0.4   # max confidence spread within a single source before flagging conflict
_DIVERSITY_BONUS_PER_SOURCE    = 0.2   # quality bonus per unique evidence source (5 sources → max)
_DIVERSITY_BONUS_CAP           = 1.0   # maximum diversity bonus before weighting
_QUALITY_BASE_WEIGHT           = 0.7   # weight given to avg adjusted confidence in final score
_QUALITY_DIVERSITY_WEIGHT      = 0.3   # weight given to diversity bonus in final score
_LOW_CONFIDENCE_THRESHOLD      = 0.3   # avg adjusted confidence below this triggers very_low flag
_SELF_REPORTED_QUALITY_PENALTY = 0.5   # multiplier applied when all evidence is self-reported
_SIGNATURE_VALID_BONUS         = 0.15  # additive bonus applied to trust_multiplier when signature verifies
_SIGNATURE_INVALID_MULTIPLIER  = 0.1   # trust_multiplier override when signature is present but invalid

# Cross-validation constants
_CROSS_VALIDATION_AGREEMENT_THRESHOLD = 0.3   # agreement above this → validator "agrees"
_CROSS_VALIDATION_CONFLICT_THRESHOLD  = -0.3  # agreement below this → validator "conflicts"
_CROSS_VALIDATION_AGREEMENT_BONUS     = 0.05  # quality bonus per agreeing validator call
_CROSS_VALIDATION_CONFLICT_PENALTY    = 0.15  # quality penalty per conflicting validator call


def classify_source(source: str) -> SourceTrust:
    src_lower = source.lower()
    for kw, trust in _SOURCE_TRUST_MAP.items():
        if kw in src_lower:
            return trust
    return SourceTrust.UNKNOWN


def _canonical_evidence_bytes(source: str, content: str) -> bytes:
    """Deterministic bytes over which evidence signatures are computed."""
    data = {"content": content, "source": source}
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode()


def _verify_evidence_signature(item: EvidenceItem) -> bool | None:
    """
    Verify the Ed25519 signature on an EvidenceItem.

    Returns True  — signature present and valid
            False — signature present but invalid
            None  — no signature (unsigned evidence)
    """
    if item.signature is None and item.signed_by is None:
        return None
    if item.signature is None or item.signed_by is None:
        # One field present without the other — treat as malformed / invalid
        return False

    try:
        sig_bytes = base64.b64decode(item.signature)
        pub_bytes = base64.b64decode(item.signed_by)
        data = _canonical_evidence_bytes(item.source, item.content)

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(sig_bytes, data)  # raises InvalidSignature on failure
        except ImportError:
            # Offline fallback: HMAC-SHA256 (mirrors crypto/signing.py offline mode)
            import hashlib as _hashlib
            import hmac as _hmac
            expected = _hmac.new(pub_bytes, data, _hashlib.sha256).digest()
            if not _hmac.compare_digest(expected, sig_bytes):
                raise ValueError("HMAC verification failed (offline mode)")

        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Cross-validation types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CrossValidationResult:
    """Result from one CrossValidator for one EvidenceItem."""
    validator_name: str
    item_source:    str
    agreement:      float  # -1.0 (strong disagreement) to 1.0 (strong agreement)
    notes:          str


@runtime_checkable
class CrossValidator(Protocol):
    """
    Protocol for independent external cross-validators.

    Implementations query an independent source (threat-intel feed,
    second SIEM, external sensor API, etc.) and return an agreement score
    comparing that source's view against the submitted EvidenceItem.

    agreement > _CROSS_VALIDATION_AGREEMENT_THRESHOLD  → boosts quality_score
    agreement < _CROSS_VALIDATION_CONFLICT_THRESHOLD   → penalises quality_score
                                                          + sets cross_validation_conflict flag
    """

    @property
    def name(self) -> str:
        """Unique identifier for this validator (used in audit logs)."""
        ...

    def validate(self, item: EvidenceItem) -> CrossValidationResult:
        """
        Query the independent source and score agreement with *item*.

        Must not raise; return agreement=0.0 with an explanatory notes
        string on any retrieval failure.
        """
        ...


# ---------------------------------------------------------------------------
# Evidence evaluation result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceEvaluation:
    """Evaluation result for the evidence set."""
    quality_score:            float          # 0.0 (poor) to 1.0 (good)
    item_evaluations:         list[dict]     # per-item breakdown
    conflicts:                list[str]      # conflicting evidence pairs
    flags:                    dict[str, bool]
    summary:                  str
    cross_validation_results: list[dict] = field(default_factory=list)  # per-validator results

    def explain(self) -> str:
        lines = [f"EvidenceEvaluation: quality={self.quality_score:.3f}"]
        for ie in self.item_evaluations:
            lines.append(
                f"  [{ie['trust']}] {ie['source'][:30]:<30} "
                f"raw={ie['raw_confidence']:.2f} → "
                f"adjusted={ie['adjusted_confidence']:.2f}"
            )
        if self.conflicts:
            lines.append(f"  CONFLICTS: {self.conflicts}")
        if self.cross_validation_results:
            lines.append(f"  cross_validation ({len(self.cross_validation_results)} result(s)):")
            for cv in self.cross_validation_results:
                lines.append(
                    f"    [{cv['validator']}] {cv['source'][:25]:<25} "
                    f"agreement={cv['agreement']:+.2f}  {cv['notes']}"
                )
        if self.flags:
            lines.append(f"  flags: {self.flags}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# EvidenceEvaluator
# ---------------------------------------------------------------------------

class EvidenceEvaluator:
    """
    evaluates the evidence list and returns an epistemic quality score。

    high quality_score → evidence is sufficient and trustworthy (reduces risk)
    low quality_score  → evidence is insufficient or untrustworthy (raises risk)

    Optional CrossValidators run after internal scoring.  Each validator
    queries an independent external source; agreement boosts quality_score
    while disagreement lowers it and sets the cross_validation_conflict flag.
    """

    def __init__(self, cross_validators: list[CrossValidator] | None = None) -> None:
        self._validators: list[CrossValidator] = list(cross_validators) if cross_validators else []

    def register_validator(self, validator: CrossValidator) -> None:
        """Attach an additional CrossValidator.  Thread-unsafe; call before evaluate()."""
        self._validators.append(validator)

    def evaluate(self, evidence: list[EvidenceItem]) -> EvidenceEvaluation:
        if not evidence:
            return EvidenceEvaluation(
                quality_score=0.0,
                item_evaluations=[],
                conflicts=[],
                flags={"no_evidence": True},
                summary="No evidence provided",
            )

        item_evals = []
        adjusted_confidences = []
        sources_seen: dict[str, list[float]] = {}
        flags: dict[str, bool] = {}

        has_invalid_signature = False
        for item in evidence:
            trust = classify_source(item.source)
            multiplier = _TRUST_MULTIPLIER[trust]
            raw_conf = item.confidence if item.confidence is not None else 0.5

            sig_result = _verify_evidence_signature(item)
            if sig_result is True:
                # Verified signature — boost effective trust
                multiplier = min(1.0, multiplier + _SIGNATURE_VALID_BONUS)
                sig_status = "valid"
            elif sig_result is False:
                # Signature present but verification failed — heavily penalize
                multiplier = _SIGNATURE_INVALID_MULTIPLIER
                sig_status = "invalid"
                has_invalid_signature = True
            else:
                sig_status = "unsigned"

            adjusted = raw_conf * multiplier

            item_evals.append({
                "source":              item.source,
                "trust":               trust.value,
                "raw_confidence":      raw_conf,
                "trust_multiplier":    round(multiplier, 3),
                "adjusted_confidence": round(adjusted, 3),
                "signature_status":    sig_status,
            })
            adjusted_confidences.append(adjusted)

            # record confidence per source (for conflict detection)
            base_source = item.source.split("/")[0].split(":")[0].lower()
            sources_seen.setdefault(base_source, []).append(raw_conf)

        if has_invalid_signature:
            flags["signature_invalid"] = True

        # conflict detection: same source reporting widely different confidence values
        conflicts = []
        for src, confs in sources_seen.items():
            if len(confs) >= 2:
                max_diff = max(confs) - min(confs)
                if max_diff >= _CONFLICT_CONFIDENCE_THRESHOLD:
                    conflicts.append(
                        f"{src}: confidences {confs} differ by {max_diff:.2f}"
                    )

        if conflicts:
            flags["conflicting_evidence"] = True

        # overall summary
        avg_adjusted = sum(adjusted_confidences) / len(adjusted_confidences)
        unique_sources = len({e.source.split("/")[0].lower() for e in evidence})

        # quality_score: avg adjusted confidence × source diversity bonus
        diversity_bonus = min(_DIVERSITY_BONUS_CAP, unique_sources * _DIVERSITY_BONUS_PER_SOURCE)
        quality_score = avg_adjusted * (_QUALITY_BASE_WEIGHT + diversity_bonus * _QUALITY_DIVERSITY_WEIGHT)

        if avg_adjusted < _LOW_CONFIDENCE_THRESHOLD:
            flags["very_low_adjusted_confidence"] = True
        if unique_sources == 1:
            flags["single_source"] = True

        # check if all evidence is self-reported
        all_self_reported = all(
            classify_source(e.source) == SourceTrust.SELF_REPORTED
            for e in evidence
        )
        if all_self_reported:
            flags["all_self_reported"] = True
            quality_score *= _SELF_REPORTED_QUALITY_PENALTY

        # ── Cross-validation against independent external sources ──────────
        cv_results: list[dict] = []
        if self._validators:
            for item in evidence:
                for validator in self._validators:
                    try:
                        cv = validator.validate(item)
                    except Exception as exc:
                        cv = CrossValidationResult(
                            validator_name=getattr(validator, "name", "unknown"),
                            item_source=item.source,
                            agreement=0.0,
                            notes=f"validator error: {exc}",
                        )
                    cv_results.append({
                        "validator":  cv.validator_name,
                        "source":     cv.item_source,
                        "agreement":  cv.agreement,
                        "notes":      cv.notes,
                    })

            flags["cross_validated"] = True

            agreeing   = sum(1 for r in cv_results if r["agreement"] >= _CROSS_VALIDATION_AGREEMENT_THRESHOLD)
            conflicting = sum(1 for r in cv_results if r["agreement"] <= _CROSS_VALIDATION_CONFLICT_THRESHOLD)

            quality_score += agreeing   * _CROSS_VALIDATION_AGREEMENT_BONUS
            quality_score -= conflicting * _CROSS_VALIDATION_CONFLICT_PENALTY
            quality_score  = max(0.0, min(1.0, quality_score))

            if conflicting:
                flags["cross_validation_conflict"] = True

        return EvidenceEvaluation(
            quality_score=round(quality_score, 4),
            item_evaluations=item_evals,
            conflicts=conflicts,
            flags=flags,
            summary=(
                f"{len(evidence)} items, "
                f"avg_adjusted={avg_adjusted:.2f}, "
                f"{unique_sources} unique source(s)"
            ),
            cross_validation_results=cv_results,
        )
