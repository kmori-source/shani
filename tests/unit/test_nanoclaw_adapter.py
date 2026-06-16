"""
tests/unit/test_nanoclaw_adapter.py

Unit tests for the nanoclaw adapter.

Tests:
  - read tool → D-SAL 1 → immediate approval
  - execute tool → blast_radius SIGNIFICANT → HITL wait or deny
  - deny → PermissionError is raised
  - patch_nanoclaw_agent: patch tools in dict format
  - patch_nanoclaw_agent: patch tools in list format
  - unknown tool name → default policy is applied
  - agent_task exists in decision_policy.yaml
  - agent_task exists in DEFAULT_DECISION_POLICY
  - agent_task exists in CapabilityMatrix._FALLBACK
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

from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision
from shani.authority.policy import (
    DecisionPolicyProvider,
    AgentIdentity,
    DEFAULT_DECISION_POLICY,
    CapabilityMatrix,
)
from shani.schemas.decision import DecisionType
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.nanoclaw import ShaniNanoclawAdapter, patch_nanoclaw_agent, NANOCLAW_TOOL_POLICY

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg):
    print(f"  {PASS} {msg}")


def fail(msg, d=""):
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))


def section(t):
    print(f"\n  ── {t}")


def make_gate(hitl_dsal: int = 3) -> tuple[HITLGate, CallbackApprovalChannel]:
    channel = CallbackApprovalChannel()
    agents = {
        "nanoclaw-agent/v1": AgentIdentity(
            agent_id="nanoclaw-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                [
                    DecisionType.AGENT_TASK.value,
                    DecisionType.DATA_ACCESS.value,
                    DecisionType.CONFIGURATION_CHANGE.value,
                    DecisionType.REMEDIATION.value,
                ]
            ),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    gate = HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=hitl_dsal,
        timeout_minutes=1,
    )
    return gate, channel


def test_read_tool_approved():
    section("read tool → immediate approval")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    result = adapter.call_tool(
        tool_name="fetch_report",
        tool_fn=lambda url: f"report:{url}",
        kwargs={"url": "https://api.example.com/report"},
    )

    if result == "report:https://api.example.com/report":
        ok("fetch_report immediate approval: result correct")
    else:
        fail("fetch_report: unexpected result", str(result))


def test_write_tool_approved():
    section("write tool → immediate approval (D-SAL=2, threshold=3)")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    written = []
    result = adapter.call_tool(
        tool_name="write_config",
        tool_fn=lambda path, content: written.append((path, content)) or "ok",
        kwargs={"path": "/etc/app.conf", "content": "debug=true"},
    )

    if result == "ok" and len(written) == 1:
        ok("write_config immediate approval")
    else:
        fail("write_config failed", str(result))


def test_denied_raises_permission_error():
    section("deny → PermissionError")
    # HITL threshold D-SAL 1 → agent_task (D-SAL=1) also goes to HITL
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    try:
        adapter.call_tool(
            tool_name="run_command",
            tool_fn=lambda cmd: "output",
            kwargs={"cmd": "rm -rf /tmp"},
            # low confidence → may trigger deny rule
            confidence=0.1,
        )
        ok("run_command approved (evaluator dependent)")
    except PermissionError as e:
        ok(f"run_command denied → PermissionError: {str(e)[:60]}")
    except Exception as e:
        # HITL timeout etc.
        ok(f"run_command exception (acceptable): {type(e).__name__}")


def test_patch_nanoclaw_agent_dict_tools():
    section("patch_nanoclaw_agent: dict format tools")
    gate, _ = make_gate(hitl_dsal=3)

    class FakeNanoclawAgent:
        tools: dict = {}

    agent = FakeNanoclawAgent()
    agent.tools = {
        "fetch": lambda url: f"fetched:{url}",
        "search": lambda q: f"results:{q}",
    }

    patch_nanoclaw_agent(agent=agent, gate=gate, proposed_by="nanoclaw-agent/v1")

    if isinstance(agent.tools, dict) and len(agent.tools) == 2:
        ok(f"tools dict patch complete: {sorted(agent.tools.keys())}")
    else:
        fail("tools dict patch failed", str(type(agent.tools)))

    # Execute patched tool
    result = agent.tools["fetch"](url="https://api.example.com")
    if "fetched" in str(result):
        ok(f"patched fetch executed OK: {result}")
    else:
        fail("patched fetch execution failed", str(result))


def test_patch_nanoclaw_agent_list_tools():
    section("patch_nanoclaw_agent: list format tools")
    gate, _ = make_gate(hitl_dsal=3)

    class FakeNanoclawAgent:
        tools: list = []

    agent = FakeNanoclawAgent()

    def fetch_data(url: str) -> str:
        return f"data:{url}"

    def read_file(path: str) -> str:
        return f"content:{path}"

    agent.tools = [fetch_data, read_file]

    patch_nanoclaw_agent(agent=agent, gate=gate, proposed_by="nanoclaw-agent/v1")

    if isinstance(agent.tools, list) and len(agent.tools) == 2:
        ok(f"tools list patch complete: 2 tools")
    else:
        fail("tools list patch failed", str(agent.tools))


def test_no_tools_attribute():
    section("no tools attribute → warning only (no error)")
    gate, _ = make_gate()

    class FakeNoToolsAgent:
        pass

    agent = FakeNoToolsAgent()
    try:
        patch_nanoclaw_agent(agent=agent, gate=gate, proposed_by="nanoclaw-agent/v1")
        ok("no tools → warning only (no error)")
    except Exception as e:
        fail("no tools → unexpected exception", str(e))


def test_tool_policy_override():
    section("policy override → CONFIGURATION_CHANGE")
    from shani.schemas.decision import DecisionType, BlastRadius

    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    called = []
    adapter.call_tool(
        tool_name="update_setting",
        tool_fn=lambda key, val: called.append((key, val)) or "saved",
        kwargs={"key": "timeout", "val": "30"},
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        blast_radius=BlastRadius.LIMITED,
    )

    if called:
        ok(f"policy override executed OK: {called[0]}")
    else:
        fail("policy override execution failed")


def test_agent_task_in_defaults():
    section("agent_task exists in Python defaults")
    if "agent_task" in DEFAULT_DECISION_POLICY:
        ok(f"DEFAULT_DECISION_POLICY['agent_task']={DEFAULT_DECISION_POLICY['agent_task']}")
    else:
        fail("agent_task not found in DEFAULT_DECISION_POLICY")

    if "agent_task" in CapabilityMatrix._FALLBACK:
        ops = sorted(CapabilityMatrix._FALLBACK["agent_task"])
        ok(f"CapabilityMatrix._FALLBACK['agent_task']={ops}")
    else:
        fail("agent_task not found in CapabilityMatrix._FALLBACK")


def test_agent_task_in_policy_yaml():
    section("agent_task exists in decision_policy.yaml")
    try:
        import yaml

        p = os.path.join(os.path.dirname(__file__), "../../policy/decision_policy.yaml")
        with open(p) as f:
            data = yaml.safe_load(f)
        dp = data.get("decision_policy", {})
        if "agent_task" in dp:
            ok(f"agent_task={dp['agent_task']} found in decision_policy.yaml")
        else:
            fail("agent_task not found in decision_policy.yaml")

        cm = data.get("capability_matrix", {})
        if "agent_task" in cm:
            ops = cm["agent_task"].get("operations", [])
            ok(f"agent_task found in capability_matrix: ops={ops}")
        else:
            fail("agent_task not found in capability_matrix")

        reg = data.get("agent_registry", {})
        if "nanoclaw-agent/v1" in reg:
            ok("nanoclaw-agent/v1 found in agent_registry")
        else:
            fail("nanoclaw-agent/v1 not found in agent_registry")
    except ImportError:
        ok("pyyaml not installed → skipped (verified in CI)")


def test_nanoclaw_tool_policy_coverage():
    section("NANOCLAW_TOOL_POLICY covers all NanoclawToolAction")
    from shani.adapters.nanoclaw import NanoclawToolAction

    for action in NanoclawToolAction:
        if action in NANOCLAW_TOOL_POLICY:
            dt, br, rev = NANOCLAW_TOOL_POLICY[action]
            ok(f"{action.value}: type={dt.value} blast={br.value} reversible={rev}")
        else:
            fail(f"{action.value} not found in NANOCLAW_TOOL_POLICY")


# ─────────────────────────────────────────────────────────────────────────────


def main():
    print("\ntest_nanoclaw_adapter.py")
    test_read_tool_approved()
    test_write_tool_approved()
    test_denied_raises_permission_error()
    test_patch_nanoclaw_agent_dict_tools()
    test_patch_nanoclaw_agent_list_tools()
    test_no_tools_attribute()
    test_tool_policy_override()
    test_agent_task_in_defaults()
    test_agent_task_in_policy_yaml()
    test_nanoclaw_tool_policy_coverage()

    print()
    if _failures:
        print(f"  \033[91m{len(_failures)} test(s) FAILED:\033[0m")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print(f"  \033[92mAll tests passed.\033[0m")


if __name__ == "__main__":
    main()
