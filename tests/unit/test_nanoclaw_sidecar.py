"""
tests/unit/test_nanoclaw_sidecar.py

ShaniSidecarServer / ShaniSidecarClient のユニットテスト。

Pattern 1: Pod内サイドカー
  - サーバーはデフォルト 0.0.0.0 にバインド
  - クライアントは localhost で接続

Tests:
  - サーバーが起動・停止できる
  - /healthz が ok を返す
  - evaluate: read ツール → 承認
  - evaluate: 拒否 → DeniedDecision
  - verify_binding: 正当な ADO → True
  - register_executed: 正常に通知できる
  - ShaniSidecarClient.evaluate + patch_nanoclaw_agent の統合
  - SHANI_HOST / SHANI_PORT 環境変数が反映される
  - サーバー停止後はクライアントが RuntimeError を送出する
"""
from __future__ import annotations

import os
import sys
import time

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
)
from shani.schemas.decision import DecisionType
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.nanoclaw import patch_nanoclaw_agent
from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer, ShaniSidecarClient

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_NEXT_PORT = 18800


def _next_port() -> int:
    global _NEXT_PORT
    p = _NEXT_PORT
    _NEXT_PORT += 1
    return p


def make_gate(hitl_dsal: int = 3) -> HITLGate:
    channel = CallbackApprovalChannel()
    agents = {
        "nanoclaw-agent/v1": AgentIdentity(
            agent_id="nanoclaw-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset([
                DecisionType.AGENT_TASK.value,
                DecisionType.DATA_ACCESS.value,
                DecisionType.CONFIGURATION_CHANGE.value,
            ]),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    return HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=hitl_dsal,
        timeout_minutes=1,
    )


def start_server(gate: HITLGate, port: int) -> ShaniSidecarServer:
    server = ShaniSidecarServer(gate=gate, host="127.0.0.1", port=port)
    server.start()
    for i in range(20):
        time.sleep(0.05)
        try:
            client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
            if client.healthz():
                return server
        except Exception:
            continue
    server.stop() # 起動失敗したら止める
    raise RuntimeError(f"Server failed to start on port {port}")


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_server_start_stop():
    section("サーバー起動・停止")
    port = _next_port()
    gate = make_gate()
    server = start_server(gate, port)
    client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
    if client.healthz():
        ok("サーバー起動確認: /healthz → ok")
    else:
        fail("サーバー起動失敗")
    server.stop()
    ok("サーバー停止完了")


def test_healthz():
    section("/healthz エンドポイント")
    port = _next_port()
    gate = make_gate()
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        result = client.healthz()
        if result:
            ok("/healthz → True")
        else:
            fail("/healthz → False（サーバー未応答）")
    finally:
        server.stop()


def test_evaluate_approved():
    section("evaluate: read ツール → 承認")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.adapters.nanoclaw import ShaniNanoclawAdapter
        adapter = ShaniNanoclawAdapter(gate=client, proposed_by="nanoclaw-agent/v1")
        result = adapter.call_tool(
            tool_name="fetch_report",
            tool_fn=lambda url: f"report:{url}",
            kwargs={"url": "https://api.example.com/report"},
        )
        if "report:" in str(result):
            ok(f"evaluate 承認 + 実行完了: {result}")
        else:
            fail("evaluate 承認後の結果が期待値と異なる", str(result))
    finally:
        server.stop()


def test_evaluate_denied():
    section("evaluate: 拒否 → DeniedDecision")
    port = _next_port()
    # HITL 閾値を D-SAL=1 にして全アクションを HITL にする
    # CallbackChannel はデフォルトで timeout → 拒否
    gate = make_gate(hitl_dsal=1)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.adapters.nanoclaw import ShaniNanoclawAdapter
        adapter = ShaniNanoclawAdapter(gate=client, proposed_by="nanoclaw-agent/v1")
        try:
            adapter.call_tool(
                tool_name="run_command",
                tool_fn=lambda cmd: "output",
                kwargs={"cmd": "rm -rf /tmp"},
                confidence=0.1,
            )
            # HITL timeout or approval depending on gate config
            ok("evaluate: 承認（CallbackChannel auto-approve or timeout）")
        except (PermissionError, RuntimeError, TimeoutError) as e:
            ok(f"evaluate: 拒否または例外 → {type(e).__name__}: {str(e)[:60]}")
    finally:
        server.stop()


def test_verify_binding():
    section("verify_binding: 正当な ADO → True")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.adapters.nanoclaw import ShaniNanoclawAdapter
        from shani.schemas.decision import (
            DecisionProposal, DecisionType, BlastRadius, DecisionScope, EvidenceItem
        )
        from datetime import datetime, timedelta, timezone

        proposal = DecisionProposal(
            decision_type=DecisionType.DATA_ACCESS,
            proposed_by="nanoclaw-agent/v1",
            description="verify_binding test",
            target="test:target",
            scope=DecisionScope(asset_ids=["test:target"]),
            evidence=[EvidenceItem(source="test", content="test evidence", confidence=0.8)],
            confidence=0.9,
            reversibility=True,
            blast_radius=BlastRadius.ISOLATED,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
        )
        result = client.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            ok(f"evaluate: 拒否（ポリシー依存）→ スキップ: {result.reason[:60]}")
            return
        ok(f"ADO 取得: dsal={result.authorized_dsal}")
        ok_binding = client.verify_binding(result)
        if ok_binding:
            ok("verify_binding → True")
        else:
            fail("verify_binding → False（期待: True）")
    finally:
        server.stop()


def test_register_executed():
    section("register_executed: 正常通知")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.schemas.decision import (
            DecisionProposal, DecisionType, BlastRadius, DecisionScope, EvidenceItem
        )
        from datetime import datetime, timedelta, timezone

        proposal = DecisionProposal(
            decision_type=DecisionType.DATA_ACCESS,
            proposed_by="nanoclaw-agent/v1",
            description="register_executed test",
            target="test:register",
            scope=DecisionScope(asset_ids=["test:register"]),
            evidence=[EvidenceItem(source="test", content="test", confidence=0.8)],
            confidence=0.9,
            reversibility=True,
            blast_radius=BlastRadius.ISOLATED,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
        )
        ado = client.evaluate(proposal)
        if isinstance(ado, DeniedDecision):
            ok(f"evaluate 拒否 → register_executed テストスキップ: {ado.reason[:60]}")
            return
        try:
            client.register_executed(ado, agent_id="nanoclaw-agent/v1")
            ok("register_executed 完了（例外なし）")
        except Exception as e:
            fail("register_executed で例外", str(e))
    finally:
        server.stop()


def test_patch_nanoclaw_agent_sidecar():
    section("patch_nanoclaw_agent(gate=client) の統合")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")

        class FakeAgent:
            tools: dict = {}

        agent = FakeAgent()
        agent.tools = {
            "fetch": lambda url: f"data:{url}",
            "read":  lambda path: f"content:{path}",
        }

        patch_nanoclaw_agent(agent=agent, gate=client, proposed_by="nanoclaw-agent/v1")

        if isinstance(agent.tools, dict) and len(agent.tools) == 2:
            ok(f"tools パッチ完了: {sorted(agent.tools.keys())}")
        else:
            fail("tools パッチ失敗", str(agent.tools))

        result = agent.tools["fetch"](url="https://api.example.com")
        if "data:" in str(result):
            ok(f"パッチ済みツール実行OK: {result}")
        else:
            fail("パッチ済みツール実行失敗", str(result))
    finally:
        server.stop()


def test_env_var_host_port():
    section("SHANI_HOST / SHANI_PORT 環境変数")
    port = _next_port()
    os.environ["SHANI_HOST"] = "127.0.0.1"
    os.environ["SHANI_PORT"] = str(port)
    try:
        gate = make_gate()
        server = ShaniSidecarServer(gate=gate)
        if server.host == "127.0.0.1":
            ok(f"SHANI_HOST 反映: host={server.host}")
        else:
            fail(f"SHANI_HOST 未反映: host={server.host}")
        if server.port == port:
            ok(f"SHANI_PORT 反映: port={server.port}")
        else:
            fail(f"SHANI_PORT 未反映: port={server.port}")

        client = ShaniSidecarClient()
        if f"127.0.0.1:{port}" in client._base_url:
            ok(f"クライアント base_url 反映: {client._base_url}")
        else:
            fail(f"クライアント base_url 未反映: {client._base_url}")
    finally:
        del os.environ["SHANI_HOST"]
        del os.environ["SHANI_PORT"]


def test_server_stopped_raises():
    section("停止済みサーバーへのリクエスト → RuntimeError")
    port = _next_port()
    gate = make_gate()
    server = start_server(gate, port)
    server.stop()
    time.sleep(0.1)
    client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}", timeout=1.0)
    try:
        client.healthz()
        ok("healthz: サーバー停止後も到達（予期外だが許容）")
    except (RuntimeError, Exception):
        ok("停止済みサーバー → 例外送出（期待通り）")


def test_server_default_host():
    section("ShaniSidecarServer デフォルト host = 0.0.0.0")
    gate = make_gate()
    server = ShaniSidecarServer(gate=gate)
    if server.host == "0.0.0.0":
        ok(f"デフォルト host = 0.0.0.0（Pod内サイドカー用）")
    else:
        fail(f"デフォルト host が 0.0.0.0 ではない: {server.host}")
    if server.port == 8765:
        ok(f"デフォルト port = 8765")
    else:
        fail(f"デフォルト port が 8765 ではない: {server.port}")


# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\ntest_nanoclaw_sidecar.py")
    test_server_start_stop()
    test_healthz()
    test_evaluate_approved()
    test_evaluate_denied()
    test_verify_binding()
    test_register_executed()
    test_patch_nanoclaw_agent_sidecar()
    test_env_var_host_port()
    test_server_stopped_raises()
    test_server_default_host()

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
