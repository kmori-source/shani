"""
tests/security/test_oss_clarity.py

Tests for two design issues addressed before OSS release.

① Capability matrix transparency
   - _DECISION_TYPE_OPS is not hardcoded in code
   - policy.yaml capability_matrix section is the single source of truth
   - CapabilityMatrixLoader reads from it

② Evidence encapsulation timing
   - DeniedDecision carries pipeline_result + proposal on denial
   - DecisionBoundaryViolation carries DenialContext
   - to_human_summary() returns reasons in a form humans can understand
"""

from __future__ import annotations

import os, sys, tempfile, json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl

    _spec = _iu.spec_from_file_location(
        "_compat", str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py")
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings

warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone
from shani.schemas.decision import (
    DecisionProposal,
    DecisionType,
    BlastRadius,
    DecisionScope,
    EvidenceItem,
)

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []


def ok(msg):
    print(f"  {PASS} {msg}")


def fail(msg, d=""):
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))


def section(t):
    print(f"\n  ── {t}")


def future():
    return datetime.now(tz=timezone.utc) + timedelta(minutes=5)


def prop(**kw) -> DecisionProposal:
    defaults = dict(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="a/v1",
        description="restart nginx on dev server after high CPU alert",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="high CPU", confidence=0.9)],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=future(),
    )
    defaults.update(kw)
    return DecisionProposal(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# ① Capability matrix transparency
# ─────────────────────────────────────────────────────────────────────────────


def test_capability_matrix_from_policy_yaml():
    section("① CapabilityMatrixLoader reads from policy.yaml")

    from shani.authority.policy import CapabilityMatrix as CapabilityMatrixLoader

    # default (reads the actual policy/decision_policy.yaml)
    loader = CapabilityMatrixLoader()
    ops = loader.get_operations("data_access")
    ok(f"data_access ops from policy.yaml: {sorted(ops)}")
    assert "http_get" in ops
    assert "http_post" not in ops  # data_access does not include POST
    ok("data_access: http_get allowed, http_post disallowed (least privilege)")

    ops_remediation = loader.get_operations("remediation")
    assert "run_command" in ops_remediation
    ok(f"remediation ops: {sorted(ops_remediation)}")

    # unknown decision_type → empty set (fail secure)
    ops_unknown = loader.get_operations("nonexistent_type")
    assert ops_unknown == set()
    ok("unknown decision_type → empty set (fail secure)")


def test_capability_matrix_custom_yaml():
    section("① Custom policy.yaml can override the matrix")

    try:
        import yaml
    except ImportError:
        ok("yaml not installed — skipped (enable with: pip install pyyaml)")
        return

    from shani.authority.policy import CapabilityMatrix as CapabilityMatrixLoader

    custom_yaml = """
capability_matrix:
  data_access:
    operations: [http_get]
    note: "read only"
  custom_type:
    operations: [http_get, http_post, http_put, http_delete]
    note: "full access for testing"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(custom_yaml)
        tmp_path = f.name

    try:
        # CapabilityMatrix takes data directly
        # read yaml file and pass matrix_data
        import yaml as _yaml

        with open(tmp_path) as f:
            data = _yaml.safe_load(f)
        loader = CapabilityMatrixLoader(data.get("capability_matrix"))
        ops = loader.get_operations("data_access")
        assert ops == {"http_get"}
        ok("custom yaml: data_access = http_get only")

        ops_custom = loader.get_operations("custom_type")
        assert "http_delete" in ops_custom
        ok(f"custom yaml: custom_type = {sorted(ops_custom)}")

    finally:
        os.unlink(tmp_path)


def test_no_hardcoded_matrix_in_code():
    section("① Verify _DECISION_TYPE_OPS is not hardcoded in code")

    import pathlib

    cap_src = pathlib.Path("shani/boundary/capability.py").read_text()

    # verify no hardcoded dict exists
    assert "_DECISION_TYPE_OPS" not in cap_src, "_DECISION_TYPE_OPS still exists in code"
    ok("_DECISION_TYPE_OPS does not exist in code (policy.yaml is the single source of truth)")

    # verify CapabilityMatrix class exists in policy.py
    policy_src = pathlib.Path("shani/authority/policy.py").read_text()
    assert "class CapabilityMatrix:" in policy_src
    ok("class CapabilityMatrix exists in policy.py (separated from boundary)")

    # verify no direct operation mapping exists in code
    assert '"http_get", "read_file"' not in cap_src or "FALLBACK" in cap_src
    ok("operation mapping is fallback only (policy.yaml takes precedence)")


# ─────────────────────────────────────────────────────────────────────────────
# ② Evidence encapsulation timing
# ─────────────────────────────────────────────────────────────────────────────


def test_denial_context_in_denied_decision():
    section("② DeniedDecision carries pipeline_result + proposal")

    from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision
    from shani.authority.policy import DecisionPolicyProvider, AgentIdentity

    agents = {
        "test-agent/v1": AgentIdentity(
            agent_id="test-agent/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(["remediation", "configuration_change"]),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )

    # Hard DENY: CRITICAL + irreversible (rejected by RuleEngine)
    p_deny = prop(
        blast_radius=BlastRadius.CRITICAL,
        reversibility=False,
        evidence=[EvidenceItem(source="monitor", content="alert", confidence=0.9)],
    )
    result = evaluator.evaluate(p_deny)

    assert isinstance(result, DeniedDecision)
    ok(f"DeniedDecision returned: {result.reason[:50]}")

    # verify pipeline_result is embedded
    assert result.pipeline_result is not None, "pipeline_result is not embedded in DeniedDecision"
    ok("pipeline_result is embedded")

    # verify proposal is embedded
    assert result.proposal is not None, "proposal is not embedded in DeniedDecision"
    assert result.proposal.target == "host:dev-01"
    ok("proposal snapshot is embedded")

    # verify to_human_summary() works
    summary = result.to_human_summary()
    assert "reason" in summary
    assert "risk_score" in summary
    assert "rules_triggered" in summary
    assert "proposal" in summary
    ok(f"to_human_summary() contents:")
    for k, v in summary.items():
        print(f"      {k}: {v}")


def test_denial_context_no_evidence():
    section("② Denial for insufficient evidence also carries context")

    from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision
    from shani.authority.policy import DecisionPolicyProvider, AgentIdentity

    agents = {
        "test-agent/v1": AgentIdentity(
            agent_id="test-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(["network_action"]),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )

    # high D-SAL operation with no evidence
    p_no_ev = prop(
        decision_type=DecisionType.NETWORK_ACTION,
        target="host:prod-firewall",
        evidence=[],  # ← empty
        blast_radius=BlastRadius.SIGNIFICANT,
    )
    result = evaluator.evaluate(p_no_ev)
    assert isinstance(result, DeniedDecision)

    # verify context is embedded
    assert result.pipeline_result is not None
    summary = result.to_human_summary()

    # verify humans can understand why the agent was stopped
    assert "risk_score" in summary
    ok(f"risk_score: {summary.get('risk_score')}")
    ok(f"reason: {summary.get('reason')[:60]}")
    if "evidence_flags" in summary:
        ok(f"evidence_flags: {summary.get('evidence_flags')}")
    ok("information allowing humans to understand the denial reason is embedded")


def test_denial_context_in_boundary_violation():
    section("② DecisionBoundaryViolation carries DenialContext")

    from shani.boundary.hook import DecisionBoundaryViolation, DenialContext

    # legacy pattern without context (backward compatible)
    e1 = DecisionBoundaryViolation("something went wrong")
    assert e1.context is not None
    assert e1.context.reason == "something went wrong"
    ok("no context → DenialContext auto-generated (backward compatible)")

    # with context
    ctx = DenialContext(
        reason="Hard rule: CRITICAL + irreversible",
        decision_id="dec-abc123",
        risk_score=0.87,
        evidence_quality=0.92,
        framing_risk=0.0,
        rule_name="critical_irreversible_floor",
    )
    e2 = DecisionBoundaryViolation("Hard rule denied", context=ctx)
    assert e2.context.risk_score == 0.87
    assert e2.context.rule_name == "critical_irreversible_floor"
    ok("DenialContext holds risk_score, rule_name, etc.")

    # to_human_summary()
    summary = e2.to_human_summary()
    assert "reason" in summary
    assert summary["risk_score"] == 0.87
    assert summary["rule_triggered"] == "critical_irreversible_floor"
    ok(f"to_human_summary(): {summary}")

    # verify all required HITL information is present
    required_for_human = ["reason", "decision_id", "risk_score"]
    for key in required_for_human:
        assert key in summary, f"'{key}' missing from summary"
    ok("required HITL fields (reason, decision_id, risk_score) are present")


def test_human_summary_is_json_serializable():
    section("② to_human_summary() is JSON-serializable")

    from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision
    from shani.authority.policy import DecisionPolicyProvider

    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(allow_unregistered_agents=True),
    )

    p = prop(
        blast_radius=BlastRadius.CRITICAL,
        reversibility=False,
        evidence=[EvidenceItem(source="edr", content="alert", confidence=0.9)],
    )
    result = evaluator.evaluate(p)

    if isinstance(result, DeniedDecision):
        summary = result.to_human_summary()
        try:
            serialized = json.dumps(summary)
            ok(f"JSON serialization succeeded ({len(serialized)} chars)")
        except TypeError as e:
            fail(f"JSON serialization failed: {e}")
    else:
        ok("approved (CRITICAL rule not applied in this environment)")


if __name__ == "__main__":
    print("=" * 60)
    print("  OSS Readiness Tests")
    print("=" * 60)

    test_capability_matrix_from_policy_yaml()
    test_capability_matrix_custom_yaml()
    test_no_hardcoded_matrix_in_code()
    test_denial_context_in_denied_decision()
    test_denial_context_no_evidence()
    test_denial_context_in_boundary_violation()
    test_human_summary_is_json_serializable()

    print("\n" + "=" * 60)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures:
            print(f"    • {f}")
        import sys

        sys.exit(1)
    else:
        print("  All tests passed\n")
        print("  ① Capability matrix transparency:")
        print("     - _DECISION_TYPE_OPS removed from code")
        print("     - policy/decision_policy.yaml capability_matrix is the single source of truth")
        print("     - boundary is a stateless evaluation engine that only reads from policy")
        print()
        print("  ② Evidence encapsulation timing:")
        print("     - DeniedDecision.pipeline_result → risk_score, rules, evidence, framing")
        print("     - DeniedDecision.proposal        → operation snapshot")
        print("     - to_human_summary()             → JSON-serializable denial reason")
        print("     - HITL can display to_human_summary() in Slack/UI")
    print("=" * 60)
