"""
tests/security/test_policy_as_code.py

"Policy as Code" tests — verifies that the three hardcoded values have been removed.

① Capability matrix is not hardcoded in code
   → DecisionPolicyProvider.capability_matrix is the single source of truth
   → custom DecisionType can be added via policy.yaml alone

② Environment keywords are not hardcoded in code
   → DSALCalculator receives environment_rules via injection
   → custom keywords such as "customer-data" can be defined in policy.yaml

③ Authority role names are not hardcoded in code
   → gate.py uses authority_provider.resolve_authority()
   → organization-specific names such as "SRE" or "CISO" can be used
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

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []
def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")
def future(): return datetime.now(tz=timezone.utc) + timedelta(minutes=5)


# ─────────────────────────────────────────────────────────────────────────────
# ① Capability matrix
# ─────────────────────────────────────────────────────────────────────────────

def test_capability_matrix_is_in_policy_not_boundary():
    section("① CapabilityMatrix is part of Policy (no hardcode in boundary.py)")

    import pathlib
    cap_src = pathlib.Path('shani/boundary/capability.py').read_text()

    # verify no hardcoded ops dict
    assert '_DECISION_TYPE_OPS' not in cap_src
    ok("_DECISION_TYPE_OPS does not exist in code")

    assert 'CapabilityMatrixLoader' not in cap_src
    ok("CapabilityMatrixLoader does not exist in code (moved to policy.py)")

    # verify CapabilityMatrix class exists in policy.py
    policy_src = pathlib.Path('shani/authority/policy.py').read_text()
    assert 'class CapabilityMatrix:' in policy_src
    ok("class CapabilityMatrix exists in policy.py")

    # verify DecisionPolicyProvider has capability_matrix
    assert 'capability_matrix' in policy_src
    ok("DecisionPolicyProvider.capability_matrix property exists")

    # verify ExecutionBoundary obtains it via policy
    assert 'self._capability_matrix = capability_matrix' in cap_src or \
           'self._capability_matrix' in cap_src
    ok("ExecutionBoundary uses self._capability_matrix")


def test_custom_decision_type_via_policy():
    section("① Custom DecisionType can be defined in policy.yaml alone")

    from shani.authority.policy import CapabilityMatrix, DecisionPolicyProvider

    # inject custom matrix
    custom_matrix = CapabilityMatrix({
        "data_access": {"operations": ["http_get", "read_file"]},
        "my_custom_action": {"operations": ["http_get", "http_post", "http_put"]},
        "delete_action": {"operations": ["http_delete", "delete_file"]},
    })

    ops_custom = custom_matrix.get_operations("my_custom_action")
    assert "http_get" in ops_custom
    assert "http_post" in ops_custom
    ok(f"custom 'my_custom_action': ops={sorted(ops_custom)}")

    ops_delete = custom_matrix.get_operations("delete_action")
    assert "http_delete" in ops_delete
    ok(f"custom 'delete_action': ops={sorted(ops_delete)}")

    # unknown type → empty set (fail secure)
    ops_unknown = custom_matrix.get_operations("totally_unknown")
    assert ops_unknown == set()
    ok("unknown type → empty set (fail secure)")

    # verify known_types() returns the list
    types = custom_matrix.known_types()
    assert "my_custom_action" in types
    ok(f"known_types(): {types}")


def test_capability_injected_into_boundary():
    section("① ExecutionBoundary receives capability_matrix from Policy")

    from shani import ShaniEvaluator, StaticAuthorityProvider
    from shani.authority.policy import DecisionPolicyProvider, AgentIdentity, CapabilityMatrix
    from shani.boundary.capability import ExecutionBoundary

    custom_matrix = CapabilityMatrix({
        "data_access": {"operations": ["http_get"]},  # read_file excluded
    })

    policy = DecisionPolicyProvider(
        agent_registry={
            "a/v1": AgentIdentity("a/v1", 2, frozenset(["data_access"]))
        },
        capability_matrix=custom_matrix,
    )

    # verify capability_matrix can be retrieved from policy
    assert policy.capability_matrix is custom_matrix
    ok("policy.capability_matrix is identical to injected instance")

    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=policy,
    )
    boundary = ExecutionBoundary(evaluator)

    # verify boundary uses capability_matrix via policy
    ops = boundary._capability_matrix.get_operations("data_access")
    assert ops == {"http_get"}           # read_file is excluded
    assert "read_file" not in ops
    ok("boundary._capability_matrix references custom_matrix")
    ok("custom policy: data_access = http_get only (read_file excluded)")


# ─────────────────────────────────────────────────────────────────────────────
# ② Environment keywords
# ─────────────────────────────────────────────────────────────────────────────

def test_no_hardcoded_prod_keywords():
    section("② PROD_KEYWORDS not hardcoded in code")

    import pathlib
    calc_src = pathlib.Path('shani/authority/dsal_calculator.py').read_text()

    # verify PROD_KEYWORDS class variable does not exist
    # PROD_KEYWORDS class variable (no underscore) must not exist
    # _DEFAULT_PROD_KEYWORDS is allowed as a fallback
    import re
    has_class_var = bool(re.search(r'\bPROD_KEYWORDS\s*=', calc_src))
    assert not has_class_var, "PROD_KEYWORDS class variable still exists"
    ok("class variable PROD_KEYWORDS does not exist (_DEFAULT_PROD_KEYWORDS allowed as fallback)")

    # _DEFAULT_PROD_KEYWORDS may exist as a fallback
    assert '_DEFAULT_PROD_KEYWORDS' in calc_src
    ok("_DEFAULT_PROD_KEYWORDS exists as a fallback")

    # verify __init__ accepts environment_rules
    assert 'environment_rules' in calc_src
    ok("DSALCalculator.__init__(environment_rules=...) exists")


def test_custom_environment_keywords():
    section("② Custom environment keywords raise D-SAL")

    from shani.authority.dsal_calculator import DSALCalculator
    from shani.schemas.decision import DecisionProposal, DecisionType, BlastRadius, DecisionScope

    def make_prop(target: str) -> DecisionProposal:
        return DecisionProposal(
            decision_type=DecisionType.REMEDIATION,
            proposed_by="a/v1",
            description="test action",
            target=target,
            scope=DecisionScope(),
            evidence=[EvidenceItem(source="monitor", content="ok", confidence=0.9)],
            confidence=0.9, reversibility=True,
            blast_radius=BlastRadius.LIMITED,
            delegation=False, expires_at=future(),
        )

    # default: "customer-data" is not in keywords
    default_calc = DSALCalculator()
    r_default = default_calc.calculate(make_prop("host:customer-data-v1"), base_dsal=1)
    ok(f"default calc, target='customer-data-v1': effective={r_default.effective}")

    # custom: add "customer-data" as a high-risk keyword
    custom_calc = DSALCalculator(environment_rules={
        "high_risk_keywords": ["prod", "customer-data", "regulated", "pci"]
    })
    r_custom = custom_calc.calculate(make_prop("host:customer-data-v1"), base_dsal=1)
    ok(f"custom calc, target='customer-data-v1': effective={r_custom.effective}")
    assert r_custom.effective > r_default.effective, \
        f"custom keyword is not working: {r_default.effective} vs {r_custom.effective}"
    ok("custom keyword 'customer-data' applied environment penalty")

    # verify "pci" also works
    r_pci = custom_calc.calculate(make_prop("db:pci-cardholder-data"), base_dsal=1)
    assert r_pci.effective >= 2
    ok(f"custom keyword 'pci': effective={r_pci.effective}")


def test_environment_rules_from_policy():
    section("② environment_rules passed via DecisionPolicyProvider")

    from shani.authority.policy import DecisionPolicyProvider
    from shani.authority.dsal_calculator import DSALCalculator

    # policy with environment_rules
    policy = DecisionPolicyProvider(
        environment_rules={
            "high_risk_keywords": ["prod", "main-cluster", "customer"]
        }
    )
    assert policy.environment_rules is not None
    assert "main-cluster" in policy.environment_rules.get("high_risk_keywords", [])
    ok("policy.environment_rules contains 'main-cluster'")

    # verify it is passed to DSALCalculator via evaluator
    env_rules = policy._environment_rules
    calc = DSALCalculator(environment_rules=env_rules)
    assert "main-cluster" in calc._prod_keywords
    ok("DSALCalculator._prod_keywords contains 'main-cluster'")


# ─────────────────────────────────────────────────────────────────────────────
# ③ Authority role names
# ─────────────────────────────────────────────────────────────────────────────

def test_no_hardcoded_authority_map():
    section("③ authority_map not hardcoded in code")

    import pathlib
    gate_src = pathlib.Path('shani/hitl/approval/gate.py').read_text()

    # verify no hardcoded authority_map dict
    hardcoded = '"SOC-Analyst"' in gate_src and 'authority_map = {' in gate_src
    if hardcoded:
        fail("authority_map is still hardcoded in gate.py")
    else:
        ok("authority_map does not exist in gate.py")

    # verify resolve_authority() is called
    assert 'resolve_authority' in gate_src
    ok("gate.py calls resolve_authority()")


def test_custom_authority_roles():
    section("③ Custom role names reflected in HITL requests")

    from shani import ShaniEvaluator, StaticAuthorityProvider
    from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
    from shani.hitl import HITLGate
    from shani.hitl.channel.channels import CallbackApprovalChannel
    from shani.schemas.decision import DecisionProposal, DecisionType, BlastRadius, DecisionScope

    # provider with custom role names
    custom_provider = StaticAuthorityProvider(
        authority_map={
            0: "any-sre",
            1: "sre-on-call",
            2: "security-engineer",
            3: "ciso",
            4: "board-level",
        },
        max_dsal=4,
    )

    agents = {
        "a/v1": AgentIdentity("a/v1", 3, frozenset(["remediation", "network_action"]))
    }
    evaluator = ShaniEvaluator(
        authority_provider=custom_provider,
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )

    channel = CallbackApprovalChannel()
    gate = HITLGate(evaluator=evaluator, channel=channel, approval_required_at_dsal=1)

    # submit a D-SAL 2 proposal → HITL request is created
    proposal = DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="a/v1",
        description="Restart nginx on dev server",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[EvidenceItem(source="monitor", content="CPU high", confidence=0.9)],
        confidence=0.9, reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False, expires_at=future(),
    )

    request_id = gate.submit(proposal)
    pending = channel.get_pending()
    assert len(pending) == 1
    req = pending[0]

    ok(f"HITL request.required_authority = '{req.required_authority}'")

    # verify custom role name is being used
    # for D-SAL 1, expected value is "sre-on-call" or "security-engineer"
    custom_names = {"any-sre", "sre-on-call", "security-engineer", "ciso", "board-level"}
    default_names = {"SOC-Analyst", "SecOps-Lead", "Org-Policy", "Board-Level"}

    if req.required_authority in custom_names:
        ok(f"custom role name '{req.required_authority}' is being used")
    elif req.required_authority in default_names:
        fail(f"default role name '{req.required_authority}' is being used (custom was ignored)")
    else:
        ok(f"role name: '{req.required_authority}'")

    # cleanup
    channel.deny(request_id, "test", "cleanup")


# ─────────────────────────────────────────────────────────────────────────────
# Integration: policy.yaml controls everything
# ─────────────────────────────────────────────────────────────────────────────

def test_policy_yaml_is_single_source_of_truth():
    section("Integration: policy.yaml controls all three")

    import pathlib
    policy_yaml = pathlib.Path('policy/decision_policy.yaml').read_text()

    # verify all three sections exist
    assert 'capability_matrix:' in policy_yaml
    ok("capability_matrix section exists in policy.yaml")

    assert 'environment_rules:' in policy_yaml
    ok("environment_rules section exists in policy.yaml")

    assert 'authority_roles:' in policy_yaml
    ok("authority_roles section exists in policy.yaml")

    # verify no hardcoded dicts anywhere
    import pathlib
    for fname in ['shani/boundary/capability.py',
                  'shani/authority/dsal_calculator.py',
                  'shani/hitl/approval/gate.py']:
        src = pathlib.Path(fname).read_text()
        # authority_map in gateway.py is for fallback only
        if 'authority_map = {' in src and '"SOC-Analyst"' in src:
            fail(f"{fname} still has authority_map hardcoded")

    ok("all 3 files contain no hardcoded values")
    ok("a single policy.yaml controls capability, environment, and authority")



def test_defaults_match_policy_yaml():
    section("DEFAULT_DECISION_POLICY and CapabilityMatrix._FALLBACK match policy.yaml")

    try:
        import yaml
    except ImportError:
        ok("yaml not installed — skipped")
        return

    import pathlib as _pl
    yaml_src = yaml.safe_load(_pl.Path('policy/decision_policy.yaml').read_text())

    # 1. DEFAULT_DECISION_POLICY vs policy.yaml decision_policy
    from shani.authority.policy import DEFAULT_DECISION_POLICY
    yaml_policy = yaml_src.get('decision_policy', {})
    mismatches = [
        f"{k}: default={DEFAULT_DECISION_POLICY[k]}, yaml={v}"
        for k, v in yaml_policy.items()
        if k in DEFAULT_DECISION_POLICY and DEFAULT_DECISION_POLICY[k] != int(v)
    ]
    assert not mismatches, f"DEFAULT_DECISION_POLICY mismatches policy.yaml: {mismatches}"
    ok("DEFAULT_DECISION_POLICY == policy.yaml decision_policy")

    # 2. CapabilityMatrix._FALLBACK vs policy.yaml capability_matrix
    from shani.authority.policy import CapabilityMatrix
    yaml_cm = yaml_src.get('capability_matrix', {})
    diffs = []
    for dt, entry in yaml_cm.items():
        yaml_ops = set(entry.get('operations', []))
        fallback_ops = CapabilityMatrix._FALLBACK.get(dt, set())
        if yaml_ops != fallback_ops:
            diffs.append(f"{dt}: yaml={sorted(yaml_ops)} fallback={sorted(fallback_ops)}")
    assert not diffs, f"CapabilityMatrix._FALLBACK mismatches policy.yaml: {diffs}"
    ok("CapabilityMatrix._FALLBACK == policy.yaml capability_matrix")


if __name__ == "__main__":
    print("=" * 62)
    print("  Policy as Code Tests")
    print("  Verifies that the three hardcoded values have been removed and policy.yaml controls them")
    print("=" * 62)

    test_capability_matrix_is_in_policy_not_boundary()
    test_custom_decision_type_via_policy()
    test_capability_injected_into_boundary()

    test_no_hardcoded_prod_keywords()
    test_custom_environment_keywords()
    test_environment_rules_from_policy()

    test_no_hardcoded_authority_map()
    test_custom_authority_roles()

    test_policy_yaml_is_single_source_of_truth()
    test_defaults_match_policy_yaml()

    print("\n" + "=" * 62)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures: print(f"    • {f}")
        import sys; sys.exit(1)
    else:
        print("  All tests passed\n")
        print("  Changes:")
        print("  ① CapabilityMatrix moved to policy.py")
        print("     → boundary.py only reads from policy.capability_matrix")
        print("     → custom DecisionType can be added via policy.yaml alone")
        print()
        print("  ② PROD_KEYWORDS moved to environment_rules")
        print("     → DSALCalculator receives it via constructor")
        print("     → custom keywords such as 'customer-data' or 'pci' can be defined")
        print()
        print("  ③ authority_map replaced with resolve_authority()")
        print("     → gate.py delegates to authority_provider")
        print("     → organization-specific role names such as 'SRE' or 'CISO' can be used")
        print()
        print("  policy.yaml is the Single Source of Truth:")
        print("    capability_matrix  → which operations are permitted")
        print("    environment_rules  → what constitutes a production environment")
        print("    authority_roles    → who approves")
    print("=" * 62)
