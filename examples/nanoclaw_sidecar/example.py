"""
examples/nanoclaw_sidecar/example.py

Pattern 1: In-Pod Sidecar — example of running nanoclaw + Shani in the same Pod.

This script is for local operation verification.
In an actual Pod configuration, server.serve_forever() and agent.run() run in separate containers.

Usage:
    pip install shani
    python example.py

Environment variables:
    SHANI_HOST  Sidecar bind address (default: 0.0.0.0)
    SHANI_PORT  Port number (default: 8765)
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

    _spec = _iu.spec_from_file_location(
        "_compat", str(_pl.Path(__file__).parent.parent / "shani/_compat.py")
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
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


# ─── 1. Build Shani gate (sidecar container side) ────────────────────────────

channel = CLIApprovalChannel()

evaluator = ShaniEvaluator(
    authority_provider=StaticAuthorityProvider(max_dsal=3),
    decision_policy=DecisionPolicyProvider(
        agent_registry={
            "nanoclaw-agent/v1": AgentIdentity(
                agent_id="nanoclaw-agent/v1",
                granted_dsal=2,
                allowed_decision_types=frozenset(
                    ["agent_task", "data_access", "remediation", "configuration_change"]
                ),
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


# ─── 2. Start sidecar server (background) ────────────────────────────────────

port = int(os.environ.get("SHANI_PORT", "8765"))
server = ShaniSidecarServer(gate=gate, host="127.0.0.1", port=port)
server.start()
print(f"[sidecar] ShaniSidecarServer started on 127.0.0.1:{port}")


# Wait for the server to start
client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
for _ in range(20):
    if client.healthz():
        break
    time.sleep(0.1)
else:
    print("[sidecar] ERROR: server did not start")
    sys.exit(1)

print(f"[sidecar] healthz: ok")


# ─── 3. Define nanoclaw agent (agent container side) ─────────────────────────


class FakeNanoclawAgent:
    """Simple simulator for nanoclaw.Agent."""

    def __init__(self, name: str):
        self.name = name
        self.tools: dict = {}

    def run(self, task: str) -> str:
        print(f"[agent] Running: {task}")
        result = self.tools["fetch_data"](url="https://api.example.com/status")
        return f"Result: {result}"


agent = FakeNanoclawAgent("ops-bot")

agent.tools = {
    "fetch_data": lambda url: f"<data from {url}>",
    "write_report": lambda path, content: f"written:{path}",
}


# ─── 4. Pass the client as the gate to enable HTTP sidecar ───────────────────

patch_nanoclaw_agent(
    agent=agent,
    gate=client,  # ← Pass ShaniSidecarClient as the gate
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


# ─── 5. Run the agent ────────────────────────────────────────────────────────

if __name__ == "__main__":
    result = agent.run("Fetch the API status")
    print(f"\n[agent] Final result: {result}")
    server.stop()
