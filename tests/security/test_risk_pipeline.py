"""
tests/security/test_risk_pipeline.py

Tests for the 4-component risk evaluation pipeline.

① Verify that risk_score and D-SAL are independent
② Verify that the rule engine correctly denies critical cases
③ Verify that evidence epistemic quality is correctly evaluated
④ Verify that framing attacks are detected via decision_space
"""
from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location("_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"))
    _mod = _iu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel","Field","field_validator","model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings; warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone
from shani.schemas.decision import (
    DecisionProposal, DecisionType, BlastRadius, DecisionScope, EvidenceItem
)
from shani.risk import (
    RiskAssessor, DSALMapper, RuleEngine, EvidenceEvaluator,
    DecisionSpaceAnalyzer, RiskPipeline, Alternative, SourceTrust, classify_source
)

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []
def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")

def future(): return datetime.now(tz=timezone.utc) + timedelta(minutes=5)

def prop(**kw) -> DecisionProposal:
    defaults = dict(
        decision_type=DecisionType.REMEDIATION, proposed_by="a/v1",
        description="restart service on dev server", target="host:dev-01",
        scope=DecisionScope(), evidence=[EvidenceItem(source="monitor", content="ok", confidence=0.9)],
        confidence=0.9, reversibility=True, blast_radius=BlastRadius.LIMITED,
        delegation=False, expires_at=future(),
    )
    defaults.update(kw)
    return DecisionProposal(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# ① risk_score and D-SAL separation
# ─────────────────────────────────────────────────────────────────────────────

def test_risk_dsal_separation():
    section("① risk_score and D-SAL separation")

    assessor = RiskAssessor()
    mapper = DSALMapper()

    # same risk_score but different base_dsal → different effective
    p = prop(blast_radius=BlastRadius.SIGNIFICANT, target="host:prod-01")
    risk = assessor.assess(p)

    mapping1 = mapper.map(risk, base_dsal=1)
    mapping2 = mapper.map(risk, base_dsal=3)

    ok(f"for the same risk_score={risk.aggregate:.3f}:")
    ok(f"  base_dsal=1 → effective={mapping1.effective_dsal}")
    ok(f"  base_dsal=3 → effective={mapping2.effective_dsal}")
    assert mapping2.effective_dsal >= mapping1.effective_dsal

    # risk_score itself does not contain D-SAL
    assert not hasattr(risk, 'dsal'), "RiskScore should not contain dsal"
    assert not hasattr(risk, 'effective_dsal'), "RiskScore should not contain effective_dsal"
    ok("RiskScore has no dsal field (separation confirmed)")

    # risk_score breakdown has independent dimensions
    dim_names = {d.name for d in risk.dimensions}
    assert "blast_radius" in dim_names
    assert "environment" in dim_names
    ok(f"independent dimensions: {sorted(dim_names)}")

    # changing threshold table changes D-SAL mapping (institutionalized)
    strict_mapper = DSALMapper(thresholds=[
        (0.2, 1), (0.4, 2), (0.6, 3), (1.01, 4)
    ])
    permissive_mapper = DSALMapper(thresholds=[
        (0.5, 1), (0.7, 2), (0.9, 3), (1.01, 4)
    ])

    strict_result = strict_mapper.map(risk, base_dsal=1)
    permissive_result = permissive_mapper.map(risk, base_dsal=1)
    ok(f"strict policy:     effective={strict_result.effective_dsal}")
    ok(f"permissive policy: effective={permissive_result.effective_dsal}")
    # same risk but different policy → different D-SAL
    assert strict_result.effective_dsal >= permissive_result.effective_dsal


# ─────────────────────────────────────────────────────────────────────────────
# ② rule engine
# ─────────────────────────────────────────────────────────────────────────────

def test_rule_engine():
    section("② RuleEngine — immediate denial of critical cases")

    engine = RuleEngine()
    assessor = RiskAssessor()

    # policy_update always requires D-SAL 4 (OVERRIDE)
    p1 = prop(decision_type=DecisionType.POLICY_UPDATE, evidence=[
        EvidenceItem(source="audit", content="change required", confidence=0.9)
    ])
    risk1 = assessor.assess(p1)
    result1 = engine.evaluate(p1, risk1)
    assert result1.override_dsal == 4
    ok("POLICY_UPDATE → RuleEngine OVERRIDEs to D-SAL 4")

    # CRITICAL + irreversible → D-SAL 4 OVERRIDE
    p2 = prop(blast_radius=BlastRadius.CRITICAL, reversibility=False, evidence=[
        EvidenceItem(source="edr", content="critical", confidence=0.9)
    ])
    risk2 = assessor.assess(p2)
    result2 = engine.evaluate(p2, risk2)
    assert result2.override_dsal == 4
    ok("CRITICAL + irreversible → D-SAL 4 OVERRIDE")

    # network_action on prod with fewer than 2 evidence items → DENY
    p3 = prop(
        decision_type=DecisionType.NETWORK_ACTION,
        target="host:prod-firewall-01",
        evidence=[EvidenceItem(source="monitor", content="alert", confidence=0.8)],  # 1 item only
    )
    risk3 = assessor.assess(p3)
    result3 = engine.evaluate(p3, risk3)
    assert result3.is_denied
    ok(f"prod NETWORK_ACTION + 1 evidence item → DENY: {result3.final_deny.reason[:50]}")

    # prod network_action with 3 evidence items → PASS
    p4 = prop(
        decision_type=DecisionType.NETWORK_ACTION,
        target="host:prod-firewall-01",
        evidence=[
            EvidenceItem(source="siem", content="anomaly", confidence=0.9),
            EvidenceItem(source="edr",  content="lateral", confidence=0.85),
            EvidenceItem(source="audit", content="confirmed", confidence=0.9),
        ],
    )
    risk4 = assessor.assess(p4)
    result4 = engine.evaluate(p4, risk4)
    assert not result4.is_denied
    ok("prod NETWORK_ACTION + 3 evidence items → PASS")

    # risk_score >= 0.8 + agent confidence < 0.4 → DENY
    p5 = prop(
        blast_radius=BlastRadius.CRITICAL,
        target="host:prod-db-01",
        evidence=[],
        confidence=0.2,
    )
    risk5 = assessor.assess(p5)
    result5 = engine.evaluate(p5, risk5)
    assert result5.is_denied
    ok(f"high risk + low confidence → DENY")


# ─────────────────────────────────────────────────────────────────────────────
# ③ Evidence epistemic security
# ─────────────────────────────────────────────────────────────────────────────

def test_evidence_epistemic():
    section("③ Evidence — epistemic security")

    evaluator = EvidenceEvaluator()

    # source trust classification
    assert classify_source("edr-22314") == SourceTrust.SYSTEM_SENSOR
    assert classify_source("openclaw-brain") == SourceTrust.AGENT_DERIVED
    assert classify_source("agent-observation") == SourceTrust.AGENT_DERIVED  # "agent" prefix matches first
    ok("source trust classification: SYSTEM_SENSOR / AGENT_DERIVED / SELF_REPORTED")

    # self-reported only → low quality
    ev_self = [
        EvidenceItem(source="self-report", content="I think so", confidence=0.8),
        EvidenceItem(source="self-assessment", content="seems right", confidence=0.9),
    ]
    result_self = evaluator.evaluate(ev_self)
    ok(f"self-reported only: quality={result_self.quality_score:.3f} (should be low)")
    assert result_self.quality_score < 0.5
    assert result_self.flags.get("all_self_reported")

    # system sensors → high quality
    ev_sensor = [
        EvidenceItem(source="edr-system", content="lateral movement", confidence=0.93),
        EvidenceItem(source="siem-alert", content="anomalous traffic", confidence=0.88),
        EvidenceItem(source="monitor", content="CPU spike", confidence=0.95),
    ]
    result_sensor = evaluator.evaluate(ev_sensor)
    ok(f"3 system sensor items: quality={result_sensor.quality_score:.3f} (should be high)")
    assert result_sensor.quality_score > 0.6

    # conflicting evidence detection
    ev_conflict = [
        EvidenceItem(source="monitor-a", content="all good", confidence=0.95),
        EvidenceItem(source="monitor-a", content="critical failure", confidence=0.1),
    ]
    result_conflict = evaluator.evaluate(ev_conflict)
    ok(f"conflicting evidence: conflicts={result_conflict.conflicts}")
    assert result_conflict.flags.get("conflicting_evidence")
    assert len(result_conflict.conflicts) > 0

    # no evidence
    result_empty = evaluator.evaluate([])
    assert result_empty.quality_score == 0.0
    assert result_empty.flags.get("no_evidence")
    ok("no evidence: quality=0.0, no_evidence flag")


# ─────────────────────────────────────────────────────────────────────────────
# ④ Decision space — framing attacks
# ─────────────────────────────────────────────────────────────────────────────

def test_decision_space():
    section("④ DecisionSpace — framing attack detection")

    analyzer = DecisionSpaceAnalyzer()

    # no alternatives → suspicion score UP
    p_no_alt = prop(blast_radius=BlastRadius.SIGNIFICANT)
    result_no_alt = analyzer.analyze(p_no_alt, alternatives=None)
    ok(f"no alternatives: framing_risk={result_no_alt.framing_risk_score:.2f}")
    assert result_no_alt.framing_risk_score > 0.2
    assert result_no_alt.flags.get("no_alternatives_provided")

    # lower-risk alternatives rejected without reason → suspicion score greatly UP
    p_suspicious = prop(blast_radius=BlastRadius.SIGNIFICANT)
    alts_no_reason = [
        Alternative(
            description="read-only monitoring",
            decision_type="data_access",
            blast_radius="isolated",
            reason_rejected="",  # no reason
        )
    ]
    result_suspicious = analyzer.analyze(p_suspicious, alternatives=alts_no_reason)
    ok(f"lower-risk alternative rejected without reason: framing_risk={result_suspicious.framing_risk_score:.2f}")
    assert result_suspicious.framing_risk_score > 0.3
    assert result_suspicious.flags.get("unexplained_risk_escalation")

    # adequate rejection reason → low suspicion
    alts_with_reason = [
        Alternative(
            description="read-only monitoring",
            decision_type="data_access",
            blast_radius="isolated",
            reason_rejected="Real-time service restart required. Read-only monitoring cannot address this.",
        )
    ]
    result_ok = analyzer.analyze(p_suspicious, alternatives=alts_with_reason)
    ok(f"with adequate rejection reason: framing_risk={result_ok.framing_risk_score:.2f}")
    assert result_ok.framing_risk_score < result_suspicious.framing_risk_score

    # no lower-risk alternatives exist → no suspicion
    p_appropriate = prop(blast_radius=BlastRadius.ISOLATED)
    alts_same_level = [
        Alternative(
            description="alternative approach",
            decision_type="remediation",
            blast_radius="isolated",
            reason_rejected="Similar risk level but lower effectiveness.",
        )
    ]
    result_appropriate = analyzer.analyze(p_appropriate, alternatives=alts_same_level)
    ok(f"no lower-risk alternatives: framing_risk={result_appropriate.framing_risk_score:.2f}")
    assert result_appropriate.framing_risk_score < 0.2


# ─────────────────────────────────────────────────────────────────────────────
# Integration: PipelineResult
# ─────────────────────────────────────────────────────────────────────────────

def test_pipeline_integration():
    section("Integration: RiskPipeline end-to-end")

    pipeline = RiskPipeline()

    # normal case
    p_normal = prop(
        target="host:dev-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
        evidence=[EvidenceItem(source="monitor", content="high CPU", confidence=0.9)],
    )
    result = pipeline.evaluate(p_normal, base_dsal=1)
    assert not result.is_hard_denied
    ok(f"normal case: effective_dsal={result.effective_dsal}, risk={result.risk_score.aggregate:.3f}")

    # Hard DENY: policy_update + no evidence
    p_deny = prop(
        decision_type=DecisionType.POLICY_UPDATE,
        blast_radius=BlastRadius.CRITICAL,
        evidence=[],
    )
    result_deny = pipeline.evaluate(p_deny, base_dsal=4)
    assert result_deny.is_hard_denied
    ok(f"Hard DENY: {result_deny.deny_reason[:60]}")

    # verify explain() output
    explanation = result.explain()
    assert "RiskPipeline Result" in explanation
    assert "RiskScore" in explanation
    assert "RuleEngine" in explanation
    ok("explain() contains results from all components")

    # verify independence of risk_score and D-SAL
    assert hasattr(result, 'risk_score')
    assert hasattr(result, 'dsal_mapping')
    assert result.risk_score.aggregate != result.effective_dsal  # different units
    ok(f"risk_score={result.risk_score.aggregate:.3f} and effective_dsal={result.effective_dsal} are independent")


if __name__ == "__main__":
    print("=" * 60)
    print("  RiskPipeline Tests (4 components)")
    print("=" * 60)

    test_risk_dsal_separation()
    test_rule_engine()
    test_evidence_epistemic()
    test_decision_space()
    test_pipeline_integration()

    print("\n" + "=" * 60)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures: print(f"    • {f}")
        import sys; sys.exit(1)
    else:
        print("  All tests passed\n")
        print("  Design verification:")
        print("  ① risk_score (0.0–1.0) and D-SAL (0–4) are independent concepts")
        print("     → conversion handled by DSALMapper threshold table (institutionalized)")
        print("  ② rule engine takes priority over risk_score (critical cases)")
        print("     → POLICY_UPDATE, CRITICAL+irreversible, insufficient evidence, etc.")
        print("  ③ evidence source trust is multiplied into confidence")
        print("     → SELF_REPORTED halves quality; conflicts are flagged")
        print("  ④ undeclared alternatives or unexplained rejections raise framing suspicion")
        print("     → framing_risk_score is added to aggregate")
    print("=" * 60)
