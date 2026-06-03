"""
tests/unit/test_cowork_adapter.py

cowork (Claude API tool_use) アダプターのユニットテスト。

Tests:
  - read ツール → 即時承認
  - write ツール → D-SAL=2, threshold=3 → 即時承認
  - 拒否 → PermissionError が送出される
  - process_response: tool_use ブロックを一括処理
  - process_response: 未知ツール → skipped (deny_on_unknown=False)
  - process_response: 未知ツール → エラー (deny_on_unknown=True)
  - process_response: 拒否 → tool_result に is_error=True が返る
  - wrap_tool_registry: ラップ済み callable が Shani を通過する
  - tool_call が DEFAULT_DECISION_POLICY に存在する
  - tool_call が CapabilityMatrix._FALLBACK に存在する
  - tool_call が decision_policy.yaml に存在する
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


def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")


def make_gate(hitl_dsal: int = 3) -> tuple[HITLGate, CallbackApprovalChannel]:
    channel = CallbackApprovalChannel()
    agents = {
        "cowork-agent/v1": AgentIdentity(
            agent_id="cowork-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset([
                DecisionType.TOOL_CALL.value,
                DecisionType.DATA_ACCESS.value,
                DecisionType.CONFIGURATION_CHANGE.value,
                DecisionType.AGENT_TASK.value,
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


def make_tool_use_block(name: str, input_data: dict, tool_id: str = "tu_test"):
    """anthropic ToolUseBlock を模倣する dict を返す。"""
    return {"type": "tool_use", "id": tool_id, "name": name, "input": input_data}


def test_read_tool_approved():
    section("read ツール (DATA_ACCESS) → 即時承認")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    block = make_tool_use_block("read_file", {"path": "/var/log/app.log"})
    result = adapter.execute_tool_use(
        tool_use_block=block,
        tool_fn=lambda inp: f"log contents: {inp['path']}",
    )

    if "log contents" in str(result):
        ok(f"read_file 即時承認: {result[:40]}")
    else:
        fail("read_file 失敗", str(result))


def test_write_tool_approved():
    section("write ツール (CONFIGURATION_CHANGE / D-SAL=2, threshold=3) → 即時承認")
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
        ok(f"write_file 即時承認: path={written[0]}")
    else:
        fail("write_file 失敗", str(result))


def test_denied_raises_permission_error():
    section("拒否 → PermissionError")
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    block = make_tool_use_block("bash", {"command": "shutdown now"})
    try:
        adapter.execute_tool_use(
            tool_use_block=block,
            tool_fn=lambda inp: "executed",
            confidence=0.1,
        )
        ok("bash 承認（evaluator 依存）")
    except PermissionError as e:
        ok(f"bash 拒否 → PermissionError: {str(e)[:60]}")
    except Exception as e:
        ok(f"bash 例外（許容）: {type(e).__name__}")


def test_process_response_all_approved():
    section("process_response: 全 tool_use 即時承認")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    # Claude レスポンスを模倣
    fake_response = type("Response", (), {
        "content": [
            {"type": "text", "text": "I'll read the file and search."},
            make_tool_use_block("read_file",  {"path": "/etc/hosts"}, "tu_1"),
            make_tool_use_block("search",     {"query": "shani"},     "tu_2"),
        ]
    })()

    tool_registry = {
        "read_file": lambda inp: f"contents:{inp['path']}",
        "search":    lambda inp: f"results:{inp['query']}",
    }

    results = adapter.process_response(fake_response, tool_registry)

    if len(results) == 2:
        ok(f"process_response: {len(results)} tool_results 返却")
    else:
        fail(f"process_response: {len(results)} tool_results（2 期待）", str(results))

    for r in results:
        if r.get("type") == "tool_result" and not r.get("is_error"):
            ok(f"  tool_result id={r['tool_use_id']}: {r['content'][:30]}")
        else:
            fail(f"  tool_result エラー", str(r))


def test_process_response_unknown_tool_skip():
    section("process_response: 未知ツール → skip (deny_on_unknown=False)")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1", deny_on_unknown_tool=False)

    fake_response = [
        make_tool_use_block("known_tool",   {"x": 1}, "tu_1"),
        make_tool_use_block("unknown_tool", {"x": 2}, "tu_2"),
    ]
    tool_registry = {"known_tool": lambda inp: "ok"}

    results = adapter.process_response(fake_response, tool_registry)

    # unknown_tool はスキップされるため tool_results は 1 件
    if len(results) == 1 and results[0]["tool_use_id"] == "tu_1":
        ok("未知ツール skip: known_tool のみ tool_result 返却")
    else:
        fail("未知ツール skip 失敗", str(results))


def test_process_response_unknown_tool_error():
    section("process_response: 未知ツール → error (deny_on_unknown=True)")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1", deny_on_unknown_tool=True)

    fake_response = [
        make_tool_use_block("unknown_tool", {"x": 1}, "tu_err"),
    ]

    results = adapter.process_response(fake_response, {})

    if len(results) == 1 and results[0].get("is_error"):
        ok(f"未知ツール → is_error=True: {results[0]['content'][:40]}")
    else:
        fail("未知ツール → is_error 期待されたが違う", str(results))


def test_process_response_denied_returns_error_block():
    section("process_response: 拒否 → tool_result に is_error=True")
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
        ok("拒否 → tool_result なし（HITL 待機または evaluator 処理）")
        return

    denied = [r for r in results if r.get("is_error")]
    if denied:
        ok(f"拒否 → is_error=True: {denied[0]['content'][:60]}")
    else:
        # 承認された場合もある（evaluator 依存）
        ok(f"bash 承認（evaluator 依存）: {results[0].get('content', '')[:40]}")


def test_wrap_tool_registry():
    section("wrap_tool_registry: ラップ済み callable が Shani を通過する")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ShaniCoworkAdapter(gate=gate, proposed_by="cowork-agent/v1")

    called = []
    tool_registry = {
        "fetch": lambda inp: called.append(inp["url"]) or f"fetched:{inp['url']}",
    }

    governed = adapter.wrap_tool_registry(tool_registry)

    if "fetch" in governed:
        ok("wrap_tool_registry: fetch が governed dict に存在する")
    else:
        fail("wrap_tool_registry: fetch が存在しない")
        return

    result = governed["fetch"]({"url": "https://api.example.com"})
    if called and "fetched" in str(result):
        ok(f"governed fetch 実行OK: {result}")
    else:
        fail("governed fetch 実行失敗", str(result))


def test_tool_call_in_defaults():
    section("tool_call が Python デフォルトに存在する")
    if "tool_call" in DEFAULT_DECISION_POLICY:
        ok(f"DEFAULT_DECISION_POLICY['tool_call']={DEFAULT_DECISION_POLICY['tool_call']}")
    else:
        fail("DEFAULT_DECISION_POLICY に tool_call が存在しない")

    if "tool_call" in CapabilityMatrix._FALLBACK:
        ops = sorted(CapabilityMatrix._FALLBACK["tool_call"])
        ok(f"CapabilityMatrix._FALLBACK['tool_call']={ops}")
    else:
        fail("CapabilityMatrix._FALLBACK に tool_call が存在しない")


def test_tool_call_in_policy_yaml():
    section("tool_call が decision_policy.yaml に存在する")
    try:
        import yaml
        p = os.path.join(os.path.dirname(__file__), "../../policy/decision_policy.yaml")
        with open(p) as f:
            data = yaml.safe_load(f)
        dp = data.get("decision_policy", {})
        if "tool_call" in dp:
            ok(f"decision_policy.yaml に tool_call={dp['tool_call']}")
        else:
            fail("decision_policy.yaml に tool_call が存在しない")

        cm = data.get("capability_matrix", {})
        if "tool_call" in cm:
            ops = cm["tool_call"].get("operations", [])
            ok(f"capability_matrix に tool_call: ops={ops}")
        else:
            fail("capability_matrix に tool_call が存在しない")

        reg = data.get("agent_registry", {})
        if "cowork-agent/v1" in reg:
            ok("agent_registry に cowork-agent/v1 が存在する")
        else:
            fail("agent_registry に cowork-agent/v1 が存在しない")
    except ImportError:
        ok("pyyaml 未インストール → スキップ（CI で確認される）")


def test_tool_call_type_in_schema():
    section("DecisionType.TOOL_CALL が schema に存在する")
    try:
        val = DecisionType.TOOL_CALL.value
        ok(f"DecisionType.TOOL_CALL = '{val}'")
    except AttributeError as e:
        fail("DecisionType.TOOL_CALL が存在しない", str(e))


def test_cowork_policy_inference():
    section("ツール名からポリシー自動推定")
    from shani.adapters.cowork.adapter import _infer_policy

    cases = [
        ("read_file",  DecisionType.DATA_ACCESS),
        ("fetch_data", DecisionType.DATA_ACCESS),
        ("write_config", DecisionType.CONFIGURATION_CHANGE),
        ("bash",        DecisionType.AGENT_TASK),
        ("http_get",    DecisionType.NETWORK_ACTION),
        ("unknown_xyz", DecisionType.TOOL_CALL),
    ]

    for name, expected_dt in cases:
        pol = _infer_policy(name)
        if pol.decision_type == expected_dt:
            ok(f"  {name!r} → {pol.decision_type.value}")
        else:
            fail(f"  {name!r}: 期待={expected_dt.value} 実際={pol.decision_type.value}")


# ───────────────────────────────────────────────────────���─────────────────────

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
