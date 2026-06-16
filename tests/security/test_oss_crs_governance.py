"""
tests/security/test_oss_crs_governance.py

Tests: Shani governance of OSS-CRS agent decisions.

OSS-CRS (https://openssf.org/projects/oss-crs/) is an orchestration framework
for LLM-based autonomous bug-finding and bug-fixing systems (Cyber Reasoning Systems).

A CRS agent proposes actions before execution.  Shani evaluates each proposal:
  - Safe, low-risk actions (isolated builds) → approved.
  - Risky actions (irreversible prod patches) → denied.
  - Ensemble CRS coordination → bounded by delegation rules.
  - Kill switch → full CRS campaign suspended.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

    _spec = _iu.spec_from_file_location(
        "_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"),
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

from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import (
    BlastRadius,
    DecisionProposal,
    DecisionScope,
    DecisionType,
    EvidenceItem,
)

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg: str) -> None:
    print(f"  {PASS} {msg}")


def fail(msg: str, detail: str = "") -> None:
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n  ── {title}")


def future(minutes: int = 10) -> datetime:
    return datetime.now(tz=timezone.utc) + timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

CRS_AGENT_ID = "oss-crs/libfuzzer-crs/v1"
LLM_CRS_AGENT_ID = "oss-crs/multilang-crs/v1"
ORCHESTRATOR_ID = "oss-crs/orchestrator/v1"

_crs_agents = {
    CRS_AGENT_ID: AgentIdentity(
        agent_id=CRS_AGENT_ID,
        granted_dsal=2,
        allowed_decision_types=frozenset(
            ["agent_task", "network_action", "configuration_change", "remediation"]
        ),
    ),
    LLM_CRS_AGENT_ID: AgentIdentity(
        agent_id=LLM_CRS_AGENT_ID,
        granted_dsal=3,
        allowed_decision_types=frozenset(
            ["agent_task", "network_action", "configuration_change", "delegation"]
        ),
    ),
    ORCHESTRATOR_ID: AgentIdentity(
        agent_id=ORCHESTRATOR_ID,
        granted_dsal=3,
        allowed_decision_types=frozenset(["delegation", "agent_task"]),
    ),
}


def make_evaluator(**kw) -> ShaniEvaluator:
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=_crs_agents),
        **kw,
    )


def crs_proposal(
    *,
    agent: str = CRS_AGENT_ID,
    decision_type: DecisionType = DecisionType.AGENT_TASK,
    description: str,
    target: str,
    blast_radius: BlastRadius = BlastRadius.ISOLATED,
    reversibility: bool = True,
    evidence: list[EvidenceItem] | None = None,
    delegation: bool = False,
) -> DecisionProposal:
    return DecisionProposal(
        decision_type=decision_type,
        proposed_by=agent,
        description=description,
        target=target,
        scope=DecisionScope(asset_ids=[target]),
        evidence=evidence or [],
        confidence=0.9,
        reversibility=reversibility,
        blast_radius=blast_radius,
        delegation=delegation,
        expires_at=future(),
    )


# ---------------------------------------------------------------------------
# ① build-target: isolated container build — should be approved
# ---------------------------------------------------------------------------


def test_build_target_approved():
    section("① build-target (isolated container build) → approved")

    evaluator = make_evaluator()
    proposal = crs_proposal(
        description="Build libxml2 fuzz target inside Docker container",
        target="docker:oss-crs-builder",
        blast_radius=BlastRadius.ISOLATED,
        reversibility=True,
        evidence=[
            EvidenceItem(
                source="oss-crs/orchestrator",
                content="oss-fuzz project: libxml2, harness: xml",
                confidence=0.95,
            )
        ],
    )

    result = evaluator.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        fail("build-target was denied", result.reason)
        return

    assert result.authorized_dsal >= 1
    ok(f"build-target approved (dsal={result.authorized_dsal})")
    ok(f"authority: {result.authority}")


# ---------------------------------------------------------------------------
# ② run fuzzer without evidence — should be denied
# ---------------------------------------------------------------------------


def test_fuzzer_run_no_evidence_denied():
    section("② run fuzzer without evidence → denied (D-SAL elevation)")

    evaluator = make_evaluator()
    proposal = crs_proposal(
        decision_type=DecisionType.NETWORK_ACTION,
        description="Run libFuzzer against libxml2 xml harness",
        target="host:fuzz-sandbox-01",
        blast_radius=BlastRadius.SIGNIFICANT,
        reversibility=True,
        evidence=[],  # no evidence
    )

    result = evaluator.evaluate(proposal)

    assert isinstance(result, DeniedDecision), (
        f"Expected denial for no-evidence fuzzer run, got ADO dsal={getattr(result, 'authorized_dsal', '?')}"
    )
    ok(f"fuzzer run without evidence denied: {result.reason[:70]}")


# ---------------------------------------------------------------------------
# ③ run fuzzer with evidence — should be approved
# ---------------------------------------------------------------------------


def test_fuzzer_run_with_evidence_approved():
    section("③ run fuzzer with crash evidence → approved")

    evaluator = make_evaluator()
    proposal = crs_proposal(
        decision_type=DecisionType.NETWORK_ACTION,
        description="Run libFuzzer against libxml2 xml harness (crash corpus attached)",
        target="host:fuzz-sandbox-01",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
        evidence=[
            EvidenceItem(
                source="oss-crs/corpus-monitor",
                content="initial crash corpus 47 items; coverage baseline 12.3%",
                confidence=0.88,
            ),
            EvidenceItem(
                source="oss-crs/resource-controller",
                content="cpuset=2-3, memory=8G, llm_budget=0",
                confidence=1.0,
            ),
        ],
    )

    result = evaluator.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        fail("fuzzer run with evidence was denied", result.reason)
        return

    ok(f"fuzzer run approved (dsal={result.authorized_dsal})")
    evaluator.register_executed(result, CRS_AGENT_ID)
    ok("nonce consumed — replay prevention active")


# ---------------------------------------------------------------------------
# ④ apply_patch_build (safe reversible patch) — should be approved
# ---------------------------------------------------------------------------


def test_safe_patch_approved():
    section("④ apply_patch_build (reversible, isolated) → approved")

    evaluator = make_evaluator()
    proposal = crs_proposal(
        agent=LLM_CRS_AGENT_ID,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        description="Apply LLM-generated null-check patch to xmlParseDocument()",
        target="repo:libxml2/src/parser.c",
        blast_radius=BlastRadius.ISOLATED,
        reversibility=True,
        evidence=[
            EvidenceItem(
                source="oss-crs/crash-analyzer",
                content="crash input triggers NULL deref at parser.c:1234; patch validated via incremental build",
                confidence=0.91,
            ),
            EvidenceItem(
                source="oss-crs/builder",
                content="incremental build succeeded; regression tests pass",
                confidence=0.99,
            ),
        ],
    )

    result = evaluator.evaluate(proposal)

    if isinstance(result, DeniedDecision):
        fail("safe patch was denied", result.reason)
        return

    ok(f"patch approved (dsal={result.authorized_dsal})")
    ok(f"proposal_hash bound: {result.proposal_hash[:16]}…")


# ---------------------------------------------------------------------------
# ⑤ apply_patch to production — irreversible, significant blast → denied
# ---------------------------------------------------------------------------


def test_prod_irreversible_patch_denied():
    section("⑤ apply_patch to production (irreversible, significant) → denied")

    evaluator = make_evaluator()
    proposal = crs_proposal(
        agent=LLM_CRS_AGENT_ID,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        description="Deploy patched libxml2 binary to production CDN",
        target="host:prod-cdn-cluster",
        blast_radius=BlastRadius.SIGNIFICANT,
        reversibility=False,  # no rollback
        evidence=[
            EvidenceItem(
                source="oss-crs/builder",
                content="build succeeded",
                confidence=0.95,
            )
        ],
    )

    result = evaluator.evaluate(proposal)

    assert isinstance(result, DeniedDecision), "Expected denial for irreversible prod patch"
    ok(f"prod patch denied: {result.reason[:70]}")


# ---------------------------------------------------------------------------
# ⑥ ensemble CRS: orchestrator delegates to sub-CRS (delegation chain)
# ---------------------------------------------------------------------------


def test_ensemble_delegation_chain():
    section("⑥ ensemble CRS: orchestrator → sub-CRS delegation")

    evaluator = make_evaluator()

    # Step 1: orchestrator requests delegation authority
    orchestrator_proposal = crs_proposal(
        agent=ORCHESTRATOR_ID,
        decision_type=DecisionType.DELEGATION,
        description="Coordinate ensemble: libfuzzer-crs + multilang-crs against libxml2",
        target="campaign:libxml2-ensemble-001",
        blast_radius=BlastRadius.LIMITED,
        reversibility=True,
        delegation=True,
        evidence=[
            EvidenceItem(
                source="oss-crs/compose",
                content="ensemble-compose.yaml validated; 2 CRS agents; cpu/memory budgets defined",
                confidence=0.97,
            )
        ],
    )

    orchestrator_ado = evaluator.evaluate(orchestrator_proposal)

    if isinstance(orchestrator_ado, DeniedDecision):
        fail("orchestrator delegation denied", orchestrator_ado.reason)
        return

    ok(f"orchestrator ADO issued (dsal={orchestrator_ado.authorized_dsal})")
    ok(f"max_child_dsal={orchestrator_ado.delegation_rules.max_child_dsal}")
    ok(f"max_children={orchestrator_ado.delegation_rules.max_children}")
    ok(f"max_depth={orchestrator_ado.delegation_rules.max_depth}")

    # delegation rules prevent privilege escalation
    assert orchestrator_ado.delegation_rules.max_child_dsal < orchestrator_ado.authorized_dsal, (
        "Child D-SAL must be less than parent D-SAL (anti-escalation)"
    )
    ok("anti-escalation invariant: max_child_dsal < authorized_dsal")

    # Step 2: sub-CRS proposes build under parent ADO authority
    sub_proposal = crs_proposal(
        agent=CRS_AGENT_ID,
        decision_type=DecisionType.AGENT_TASK,
        description="Run libFuzzer on libxml2/xml harness (sub-campaign)",
        target="docker:oss-crs-libfuzzer",
        blast_radius=BlastRadius.ISOLATED,
        reversibility=True,
        evidence=[
            EvidenceItem(
                source="oss-crs/orchestrator",
                content="campaign libxml2-ensemble-001 authorized",
                confidence=0.95,
            )
        ],
    )

    sub_ado = evaluator.evaluate(sub_proposal, parent_ado=orchestrator_ado)

    if isinstance(sub_ado, DeniedDecision):
        fail("sub-CRS task denied under parent ADO", sub_ado.reason)
        return

    ok(f"sub-CRS task approved (dsal={sub_ado.authorized_dsal})")
    ok("delegation chain: orchestrator → libfuzzer-crs ✓")


# ---------------------------------------------------------------------------
# ⑦ kill switch — CRS campaign suspended
# ---------------------------------------------------------------------------


def test_kill_switch_suspends_crs_campaign():
    section("⑦ kill switch → entire CRS campaign suspended")

    evaluator = make_evaluator(kill_switch=True)

    proposal = crs_proposal(
        description="Run fuzzer (campaign in progress)",
        target="host:fuzz-sandbox-02",
        blast_radius=BlastRadius.ISOLATED,
    )

    result = evaluator.evaluate(proposal)

    assert isinstance(result, DeniedDecision), "Kill switch must deny all proposals"
    assert "kill switch" in result.reason.lower() or "Kill switch" in result.reason
    ok(f"kill switch blocked CRS proposal: {result.reason}")

    # Reactivating requires justification
    try:
        evaluator.deactivate_kill_switch(
            justification="False positive confirmed by security team",
            authorized_by="security-lead@openssf.org",
        )
        ok("kill switch deactivated with justification")
    except Exception as e:
        fail(f"deactivate_kill_switch raised: {e}")
        return

    result2 = evaluator.evaluate(proposal)
    assert not isinstance(result2, DeniedDecision), "Deactivated kill switch should allow proposals"
    ok("CRS campaign resumes after kill switch deactivation")


# ---------------------------------------------------------------------------
# ⑧ replay prevention — same ADO cannot be re-executed
# ---------------------------------------------------------------------------


def test_oss_crs_replay_prevention():
    section("⑧ replay prevention — executed ADO cannot be replayed")

    evaluator = make_evaluator()
    proposal = crs_proposal(
        description="Apply patch commit abc123 to sandbox",
        target="repo:libxml2/sandbox",
        blast_radius=BlastRadius.ISOLATED,
        evidence=[
            EvidenceItem(
                source="oss-crs/builder",
                content="patch validated",
                confidence=0.95,
            )
        ],
    )

    ado = evaluator.evaluate(proposal)
    if isinstance(ado, DeniedDecision):
        fail("patch denied unexpectedly", ado.reason)
        return

    # First execution
    evaluator.register_executed(ado, CRS_AGENT_ID)
    ok("patch applied and nonce consumed")

    # Replay attempt
    from shani.security.replay_store import NonceAlreadyConsumed

    try:
        evaluator.register_executed(ado, CRS_AGENT_ID)
        fail("replay was not blocked!")
    except NonceAlreadyConsumed:
        ok("replay of the same patch execution blocked — NonceAlreadyConsumed raised")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  OSS-CRS Governance Tests (OpenSSF Cyber Reasoning System)")
    print("=" * 60)

    test_build_target_approved()
    test_fuzzer_run_no_evidence_denied()
    test_fuzzer_run_with_evidence_approved()
    test_safe_patch_approved()
    test_prod_irreversible_patch_denied()
    test_ensemble_delegation_chain()
    test_kill_switch_suspends_crs_campaign()
    test_oss_crs_replay_prevention()

    print("\n" + "=" * 60)
    if _failures:
        print(f"  FAILED: {len(_failures)}")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All 8 tests passed.\n")
        print("  OSS-CRS governance scenarios verified:")
        print("    ① build-target (isolated container) → approved")
        print("    ② fuzzer run, no evidence → denied")
        print("    ③ fuzzer run with evidence → approved + replay guard")
        print("    ④ safe reversible patch → approved")
        print("    ⑤ irreversible prod patch → denied")
        print("    ⑥ ensemble delegation chain → anti-escalation enforced")
        print("    ⑦ kill switch → campaign suspended / resumed")
        print("    ⑧ replay prevention → executed patch cannot be re-applied")
    print("=" * 60)
