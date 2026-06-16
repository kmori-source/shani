"""
examples/nanoclaw_integration/example.py

Sample showing how to add Shani governance to a nanoclaw agent.

nanoclaw (qwibitai/nanoclaw) is a lightweight Python agent framework.
This example uses patch_nanoclaw_agent to add governance with zero code changes.

Usage:
    pip install shani nanoclaw
    python example.py

Note: If nanoclaw is not installed, simulates with FakeAgent.
"""

from __future__ import annotations

import os
import sys

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


# ─── 1. Build governance gate ─────────────────────────────────────────────────

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
    approval_required_at_dsal=2,  # D-SAL 2+ requires operator approval
    timeout_minutes=5,
)


# ─── 2. Define nanoclaw agent (normally uses nanoclaw.Agent) ──────────────────


class FakeNanoclawAgent:
    """Simple simulator for nanoclaw.Agent."""

    def __init__(self, name: str):
        self.name = name
        self.tools: dict = {}

    def run(self, task: str) -> str:
        """Execute a task (normally the LLM selects and calls tools)."""
        print(f"[{self.name}] Running: {task}")
        # Simulation: call fetch_data
        result = self.tools["fetch_data"](url="https://api.example.com/status")
        return f"Result: {result}"


agent = FakeNanoclawAgent("ops-bot")


# ─── 3. Register tools ────────────────────────────────────────────────────────


def fetch_data(url: str) -> str:
    """Fetch data from an external API (read-only)."""
    return f"<data from {url}>"


def write_report(path: str, content: str) -> str:
    """Write a report to a file (write)."""
    print(f"  Writing to {path}: {content[:40]}")
    return f"written:{path}"


agent.tools = {
    "fetch_data": fetch_data,
    "write_report": write_report,
}


# ─── 4. Add Shani governance with zero code changes ───────────────────────────

patch_nanoclaw_agent(
    agent=agent,
    gate=gate,
    proposed_by="nanoclaw-agent/v1",
    policy={
        # write_report is CONFIGURATION_CHANGE (D-SAL=2) → HITL
        "write_report": dict(
            decision_type=DecisionType.CONFIGURATION_CHANGE,
            blast_radius=BlastRadius.LIMITED,
        ),
        # fetch_data is DATA_ACCESS (D-SAL=1) → auto-approved
        "fetch_data": dict(
            decision_type=DecisionType.DATA_ACCESS,
            blast_radius=BlastRadius.ISOLATED,
        ),
    },
)

print("nanoclaw agent patched. All tool calls now go through Shani.")


# ─── 5. Run the agent ────────────────────────────────────────────────────────

if __name__ == "__main__":
    result = agent.run("Fetch the API status")
    print(f"\nFinal result: {result}")
