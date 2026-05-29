"""
examples/nanoclaw_sidecar/example.py

Pattern 1: Pod内サイドカー — nanoclaw + Shani を同一 Pod 内で動かす例。

このスクリプト自体はローカル動作確認用。
実際の Pod 構成では server.serve_forever() と agent.run() は別コンテナで動作する。

Usage:
    pip install shani
    python example.py

環境変数:
    SHANI_HOST  サイドカーのバインドアドレス（デフォルト: 0.0.0.0）
    SHANI_PORT  ポート番号（デフォルト: 8765）
"""
from __future__ import annotations

import os
import sys
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location("_compat",
        str(_pl.Path(__file__).parent.parent / "shani/_compat.py"))
    _mod = _iu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings
warnings.filterwarnings("ignore")

from shani import ShaniEvaluator, StaticAuthorityProvider
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionType, BlastRadius
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CLIApprovalChannel
from shani.adapters.nanoclaw import patch_nanoclaw_agent
from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer, ShaniSidecarClient


# ─── 1. Shani ゲートを構築（サイドカーコンテナ側） ────────────────────────────

channel = CLIApprovalChannel()

evaluator = ShaniEvaluator(
    authority_provider=StaticAuthorityProvider(max_dsal=3),
    decision_policy=DecisionPolicyProvider(
        agent_registry={
            "nanoclaw-agent/v1": AgentIdentity(
                agent_id="nanoclaw-agent/v1",
                granted_dsal=2,
                allowed_decision_types=frozenset([
                    "agent_task", "data_access", "remediation", "configuration_change"
                ]),
            )
        }
    ),
)

gate = HITLGate(
    evaluator=evaluator,
    channel=channel,
    approval_required_at_dsal=2,
    timeout_minutes=5,
)


# ─── 2. サイドカーサーバーを起動（バックグラウンド） ────────────────────────

port = int(os.environ.get("SHANI_PORT", "8765"))
server = ShaniSidecarServer(gate=gate, host="127.0.0.1", port=port)
server.start()
print(f"[sidecar] ShaniSidecarServer started on 127.0.0.1:{port}")


# サーバーが起動するまで待つ
client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
for _ in range(20):
    if client.healthz():
        break
    time.sleep(0.1)
else:
    print("[sidecar] ERROR: server did not start")
    sys.exit(1)

print(f"[sidecar] healthz: ok")


# ─── 3. nanoclaw エージェントを定義（エージェントコンテナ側） ────────────────

class FakeNanoclawAgent:
    """nanoclaw.Agent の簡易シミュレーター。"""
    def __init__(self, name: str):
        self.name = name
        self.tools: dict = {}

    def run(self, task: str) -> str:
        print(f"[agent] Running: {task}")
        result = self.tools["fetch_data"](url="https://api.example.com/status")
        return f"Result: {result}"


agent = FakeNanoclawAgent("ops-bot")

agent.tools = {
    "fetch_data":   lambda url: f"<data from {url}>",
    "write_report": lambda path, content: f"written:{path}",
}


# ─── 4. クライアントを gate として渡すだけで HTTP サイドカー化 ────────────────

patch_nanoclaw_agent(
    agent=agent,
    gate=client,   # ← ShaniSidecarClient を gate に渡す
    proposed_by="nanoclaw-agent/v1",
    policy={
        "write_report": dict(
            decision_type=DecisionType.CONFIGURATION_CHANGE,
            blast_radius=BlastRadius.LIMITED,
        ),
        "fetch_data": dict(
            decision_type=DecisionType.DATA_ACCESS,
            blast_radius=BlastRadius.ISOLATED,
        ),
    },
)

print("[agent] nanoclaw agent patched (tool calls → HTTP sidecar)")


# ─── 5. エージェントを実行 ───────────────────────────────────────────────────

if __name__ == "__main__":
    result = agent.run("Fetch the API status")
    print(f"\n[agent] Final result: {result}")
    server.stop()
