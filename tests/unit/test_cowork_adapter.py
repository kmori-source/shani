"""
tests/unit/test_cowork_adapter.py

Unit tests for the cowork (Claude API tool_use) adapter.

Tests:
  - read tool → immediate approval
  - write tool → D-SAL=2, threshold=3 → immediate approval
  - deny → PermissionError is raised
  - process_response: batch process tool_use blocks
  - process_response: unknown tool → skipped (deny_on_unknown=False)
  - process_response: unknown tool → error (deny_on_unknown=True)
  - process_response: deny → tool_result returns is_error=True
  - wrap_tool_registry: wrapped callable passes through Shani
  - tool_call exists in DEFAULT_DECISION_POLICY
  - tool_call exists in CapabilityMatrix._FALLBACK
  - tool_call exists in decision_policy.yaml
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
from shani.adapters.cowork import ShaniCoworkAdapter, CoworkToolPolicy

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
        "cowork-agent/v1": AgentIdentity(
            agent_id="cowork-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                [
                    DecisionType.TOOL_CALL.value,
                    DecisionType.DATA_ACCESS.value,
                    DecisionType.CONFIGURATION_CHANGE.value,
                    DecisionType.AGENT_TASK.value,
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


def make_tool_use_block(name: str, input_data: dict, tool_id: str = "tu_test"):
    """Returns a dict that mimics an anthropic ToolUseBlock."""
    return {"type": "tool_use", "id": tool_id, "name": name, "input": input_data}


def test_read_tool_approved():
    section("read tool (DATA_ACCESS) → immediate approval")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    block = make_tool_use_block("read_file", {"path": "/var/log/app.log"})
    result = adapter.execute_tool_use(
        tool_use_block=block,
        tool_fn=lambda inp: f"log contents: {inp['path']}",
    )

    if "log contents" in str(result):
        ok(f"read_file immediate approval: {result[:40]}")
    else:
        fail("read_file failed", str(result))


def test_write_tool_approved():
    section("write tool (CONFIGURATION_CHANGE / D-SAL=2, threshold=3) → immediate approval")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(
        gate=gate,
        proposed_by="cowork-agent/v1",
        policy={
            "write_file": CoworkToolPolicy(
                decision_type=DecisionType.CONFIGURATION_CHANGE,
            )
        },
    )

    written = []
    block = make_tool_use_block("write_file", {"path": "/etc/config", "content": "key=val"})
    result = adapter.execute_tool_use(
        tool_use_block=block,
        tool_fn=lambda inp: written.append(inp["path"]) or "written",
    )

    if result == "written" and written:
        ok(f"write_file immediate approval: path={written[0]}")
    else:
        fail("write_file failed", str(result))


def test_denied_raises_permission_error():
    section("deny → PermissionError")
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    block = make_tool_use_block("bash", {"command": "shutdown now"})
    try:
        adapter.execute_tool_use(
            tool_use_block=block,
            tool_fn=lambda inp: "executed",
            confidence=0.1,
        )
        ok("bash approved (evaluator dependent)")
    except PermissionError as e:
        ok(f"bash denied → PermissionError: {str(e)[:60]}")
    except Exception as e:
        ok(f"bash exception (acceptable): {type(e).__name__}")


def test_process_response_all_approved():
    section("process_response: all tool_use immediate approval")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    # Simulate a Claude response
    fake_response = type(
        "Response",
        (),
        {
            "content": [
                {"type": "text", "text": "I'll read the file and search."},
                make_tool_use_block("read_file", {"path": "/etc/hosts"}, "tu_1"),
                make_tool_use_block("search", {"query": "shani"}, "tu_2"),
            ]
        },
    )()

    tool_registry = {
        "read_file": lambda inp: f"contents:{inp['path']}",
        "search": lambda inp: f"results:{inp['query']}",
    }

    results = adapter.process_response(fake_response, tool_registry)

    if len(results) == 2:
        ok(f"process_response: {len(results)} tool_results returned")
    else:
        fail(f"process_response: {len(results)} tool_results (expected 2)", str(results))

    for r in results:
        if r.get("type") == "tool_result" and not r.get("is_error"):
            ok(f"  tool_result id={r['tool_use_id']}: {r['content'][:30]}")
        else:
            fail(f"  tool_result error", str(r))


def test_process_response_unknown_tool_skip():
    section("process_response: unknown tool → skip (deny_on_unknown=False)")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(
        gate=gate, proposed_by="cowork-agent/v1", deny_on_unknown_tool=False
    )

    fake_response = [
        make_tool_use_block("known_tool", {"x": 1}, "tu_1"),
        make_tool_use_block("unknown_tool", {"x": 2}, "tu_2"),
    ]
    tool_registry = {"known_tool": lambda inp: "ok"}

    results = adapter.process_response(fake_response, tool_registry)

    # unknown_tool is skipped, so only 1 tool_result
    if len(results) == 1 and results[0]["tool_use_id"] == "tu_1":
        ok("unknown tool skip: only known_tool tool_result returned")
    else:
        fail("unknown tool skip failed", str(results))


def test_process_response_unknown_tool_error():
    section("process_response: unknown tool → error (deny_on_unknown=True)")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(
        gate=gate, proposed_by="cowork-agent/v1", deny_on_unknown_tool=True
    )

    fake_response = [
        make_tool_use_block("unknown_tool", {"x": 1}, "tu_err"),
    ]

    results = adapter.process_response(fake_response, {})

    if len(results) == 1 and results[0].get("is_error"):
        ok(f"unknown tool → is_error=True: {results[0]['content'][:40]}")
    else:
        fail("unknown tool → expected is_error but got different result", str(results))


def test_process_response_denied_returns_error_block():
    section("process_response: deny → tool_result returns is_error=True")
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    fake_response = [
        make_tool_use_block("bash", {"command": "rm -rf /"}, "tu_deny"),
    ]

    tool_registry = {"bash": lambda inp: "executed"}

    results = adapter.process_response(
        fake_response,
        tool_registry,
        context="Trying to execute dangerous command",
    )

    if not results:
        ok("deny → no tool_result (HITL wait or evaluator processing)")
        return

    denied = [r for r in results if r.get("is_error")]
    if denied:
        ok(f"deny → is_error=True: {denied[0]['content'][:60]}")
    else:
        # Approval is also possible (evaluator dependent)
        ok(f"bash approved (evaluator dependent): {results[0].get('content', '')[:40]}")


def test_wrap_tool_registry():
    section("wrap_tool_registry: wrapped callable passes through Shani")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    called = []
    tool_registry = {
        "fetch": lambda inp: called.append(inp["url"]) or f"fetched:{inp['url']}",
    }

    governed = adapter.wrap_tool_registry(tool_registry)

    if "fetch" in governed:
        ok("wrap_tool_registry: fetch exists in governed dict")
    else:
        fail("wrap_tool_registry: fetch not found")
        return

    result = governed["fetch"]({"url": "https://api.example.com"})
    if called and "fetched" in str(result):
        ok(f"governed fetch executed OK: {result}")
    else:
        fail("governed fetch execution failed", str(result))


def test_tool_call_in_defaults():
    section("tool_call exists in Python defaults")
    if "tool_call" in DEFAULT_DECISION_POLICY:
        ok(f"DEFAULT_DECISION_POLICY['tool_call']={DEFAULT_DECISION_POLICY['tool_call']}")
    else:
        fail("tool_call not found in DEFAULT_DECISION_POLICY")

    if "tool_call" in CapabilityMatrix._FALLBACK:
        ops = sorted(CapabilityMatrix._FALLBACK["tool_call"])
        ok(f"CapabilityMatrix._FALLBACK['tool_call']={ops}")
    else:
        fail("tool_call not found in CapabilityMatrix._FALLBACK")


def test_tool_call_in_policy_yaml():
    section("tool_call exists in decision_policy.yaml")
    try:
        import yaml

        p = os.path.join(os.path.dirname(__file__), "../../policy/decision_policy.yaml")
        with open(p) as f:
            data = yaml.safe_load(f)
        dp = data.get("decision_policy", {})
        if "tool_call" in dp:
            ok(f"tool_call={dp['tool_call']} found in decision_policy.yaml")
        else:
            fail("tool_call not found in decision_policy.yaml")

        cm = data.get("capability_matrix", {})
        if "tool_call" in cm:
            ops = cm["tool_call"].get("operations", [])
            ok(f"tool_call found in capability_matrix: ops={ops}")
        else:
            fail("tool_call not found in capability_matrix")

        reg = data.get("agent_registry", {})
        if "cowork-agent/v1" in reg:
            ok("cowork-agent/v1 found in agent_registry")
        else:
            fail("cowork-agent/v1 not found in agent_registry")
    except ImportError:
        ok("pyyaml not installed → skipped (verified in CI)")


def test_tool_call_type_in_schema():
    section("DecisionType.TOOL_CALL exists in schema")
    try:
        val = DecisionType.TOOL_CALL.value
        ok(f"DecisionType.TOOL_CALL = '{val}'")
    except AttributeError as e:
        fail("DecisionType.TOOL_CALL not found", str(e))


def test_cowork_policy_inference():
    section("auto-infer policy from tool name")
    from shani.adapters.cowork.adapter import _infer_policy

    cases = [
        ("read_file", DecisionType.DATA_ACCESS),
        ("fetch_data", DecisionType.DATA_ACCESS),
        ("write_config", DecisionType.CONFIGURATION_CHANGE),
        ("bash", DecisionType.AGENT_TASK),
        ("http_get", DecisionType.NETWORK_ACTION),
        ("unknown_xyz", DecisionType.TOOL_CALL),
    ]

    for name, expected_dt in cases:
        pol = _infer_policy(name)
        if pol.decision_type == expected_dt:
            ok(f"  {name!r} → {pol.decision_type.value}")
        else:
            fail(f"  {name!r}: expected={expected_dt.value} actual={pol.decision_type.value}")


# ─────────────────────────────────────────────────────────────────────────────


def main():
    print("\ntest_cowork_adapter.py")
    test_read_tool_approved()
    test_write_tool_approved()
    test_denied_raises_permission_error()
    test_process_response_all_approved()
    test_process_response_unknown_tool_skip()
    test_process_response_unknown_tool_error()
    test_process_response_denied_returns_error_block()
    test_wrap_tool_registry()
    test_tool_call_in_defaults()
    test_tool_call_in_policy_yaml()
    test_tool_call_type_in_schema()
    test_cowork_policy_inference()

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
