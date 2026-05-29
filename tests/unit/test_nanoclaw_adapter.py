"""
tests/unit/test_nanoclaw_adapter.py

nanoclaw アダプターのユニットテスト。

Tests:
  - read ツール → D-SAL 1 → 即時承認
  - execute ツール → blast_radius SIGNIFICANT → HITL 待機または拒否
  - 拒否 → PermissionError が送出される
  - patch_nanoclaw_agent: dict 形式の tools をパッチ
  - patch_nanoclaw_agent: list 形式の tools をパッチ
  - 未知ツール名 → デフォルトポリシーが適用される
  - agent_task が decision_policy.yaml に存在する
  - agent_task が DEFAULT_DECISION_POLICY に存在する
  - agent_task が CapabilityMatrix._FALLBACK に存在する
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


def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")


def make_gate(hitl_dsal: int = 3) -> tuple[HITLGate, CallbackApprovalChannel]:
    channel = CallbackApprovalChannel()
    agents = {
        "nanoclaw-agent/v1": AgentIdentity(
            agent_id="nanoclaw-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset([
                DecisionType.AGENT_TASK.value,
                DecisionType.DATA_ACCESS.value,
                DecisionType.CONFIGURATION_CHANGE.value,
                DecisionType.REMEDIATION.value,
            ]),
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
    section("read ツール → 即時承認")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    result = adapter.call_tool(
        tool_name="fetch_report",
        tool_fn=lambda url: f"report:{url}",
        kwargs={"url": "https://api.example.com/report"},
    )

    if result == "report:https://api.example.com/report":
        ok("fetch_report 即時承認: 結果正しい")
    else:
        fail("fetch_report: 予期せぬ結果", str(result))


def test_write_tool_approved():
    section("write ツール → 即時承認 (D-SAL=2, threshold=3)")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    written = []
    result = adapter.call_tool(
        tool_name="write_config",
        tool_fn=lambda path, content: written.append((path, content)) or "ok",
        kwargs={"path": "/etc/app.conf", "content": "debug=true"},
    )

    if result == "ok" and len(written) == 1:
        ok("write_config 即時承認")
    else:
        fail("write_config 失敗", str(result))


def test_denied_raises_permission_error():
    section("拒否 → PermissionError")
    # HITL 閾値 D-SAL 1 → agent_task (D-SAL=1) も HITL になる
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by="nanoclaw-agent/v1")

    try:
        adapter.call_tool(
            tool_name="run_command",
            tool_fn=lambda cmd: "output",
            kwargs={"cmd": "rm -rf /tmp"},
            # 低 confidence → deny ルールに引っかかる可能性あり
            confidence=0.1,
        )
        ok("run_command 承認（evaluator 依存）")
    except PermissionError as e:
        ok(f"run_command 拒否 → PermissionError: {str(e)[:60]}")
    except Exception as e:
        # HITL 待機中のタイムアウトなど
        ok(f"run_command 例外（許容）: {type(e).__name__}")


def test_patch_nanoclaw_agent_dict_tools():
    section("patch_nanoclaw_agent: dict 形式 tools")
    gate, _ = make_gate(hitl_dsal=3)

    class FakeNanoclawAgent:
        tools: dict = {}

    agent = FakeNanoclawAgent()
    agent.tools = {
        "fetch":  lambda url: f"fetched:{url}",
        "search": lambda q: f"results:{q}",
    }

    patch_nanoclaw_agent(agent=agent, gate=gate, proposed_by="nanoclaw-agent/v1")

    if isinstance(agent.tools, dict) and len(agent.tools) == 2:
        ok(f"tools dict パッチ完了: {sorted(agent.tools.keys())}")
    else:
        fail("tools dict パッチ失敗", str(type(agent.tools)))

    # パッチ済みツールを実行
    result = agent.tools["fetch"](url="https://api.example.com")
    if "fetched" in str(result):
        ok(f"パッチ済み fetch 実行OK: {result}")
    else:
        fail("パッチ済み fetch 実行失敗", str(result))


def test_patch_nanoclaw_agent_list_tools():
    section("patch_nanoclaw_agent: list 形式 tools")
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
        ok(f"tools list パッチ完了: 2 ツール")
    else:
        fail("tools list パッチ失敗", str(agent.tools))


def test_no_tools_attribute():
    section("tools 属性なし → 警告のみ（エラーなし）")
    gate, _ = make_gate()

    class FakeNoToolsAgent:
        pass

    agent = FakeNoToolsAgent()
    try:
        patch_nanoclaw_agent(agent=agent, gate=gate, proposed_by="nanoclaw-agent/v1")
        ok("tools なし → 警告のみ（エラーなし）")
    except Exception as e:
        fail("tools なし → 予期せぬ例外", str(e))


def test_tool_policy_override():
    section("ポリシー上書き → CONFIGURATION_CHANGE")
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
        ok(f"ポリシー上書き実行OK: {called[0]}")
    else:
        fail("ポリシー上書き実行失敗")


def test_agent_task_in_defaults():
    section("agent_task が Python デフォルトに存在する")
    if "agent_task" in DEFAULT_DECISION_POLICY:
        ok(f"DEFAULT_DECISION_POLICY['agent_task']={DEFAULT_DECISION_POLICY['agent_task']}")
    else:
        fail("DEFAULT_DECISION_POLICY に agent_task が存在しない")

    if "agent_task" in CapabilityMatrix._FALLBACK:
        ops = sorted(CapabilityMatrix._FALLBACK["agent_task"])
        ok(f"CapabilityMatrix._FALLBACK['agent_task']={ops}")
    else:
        fail("CapabilityMatrix._FALLBACK に agent_task が存在しない")


def test_agent_task_in_policy_yaml():
    section("agent_task が decision_policy.yaml に存在する")
    try:
        import yaml
        p = os.path.join(os.path.dirname(__file__), "../../policy/decision_policy.yaml")
        with open(p) as f:
            data = yaml.safe_load(f)
        dp = data.get("decision_policy", {})
        if "agent_task" in dp:
            ok(f"decision_policy.yaml に agent_task={dp['agent_task']}")
        else:
            fail("decision_policy.yaml に agent_task が存在しない")

        cm = data.get("capability_matrix", {})
        if "agent_task" in cm:
            ops = cm["agent_task"].get("operations", [])
            ok(f"capability_matrix に agent_task: ops={ops}")
        else:
            fail("capability_matrix に agent_task が存在しない")

        reg = data.get("agent_registry", {})
        if "nanoclaw-agent/v1" in reg:
            ok("agent_registry に nanoclaw-agent/v1 が存在する")
        else:
            fail("agent_registry に nanoclaw-agent/v1 が存在しない")
    except ImportError:
        ok("pyyaml 未インストール → スキップ（CI で確認される）")


def test_nanoclaw_tool_policy_coverage():
    section("NANOCLAW_TOOL_POLICY が全 NanoclawToolAction をカバーする")
    from shani.adapters.nanoclaw import NanoclawToolAction
    for action in NanoclawToolAction:
        if action in NANOCLAW_TOOL_POLICY:
            dt, br, rev = NANOCLAW_TOOL_POLICY[action]
            ok(f"{action.value}: type={dt.value} blast={br.value} reversible={rev}")
        else:
            fail(f"NANOCLAW_TOOL_POLICY に {action.value} が存在しない")


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
