"""
examples/cowork_integration/example.py

Sample showing how to add Shani governance to Claude API (Anthropic) tool_use.

cowork is a multi-agent collaboration framework using Claude API's tool_use feature.
This example uses ShaniCoworkAdapter to verify tool_use blocks returned by Claude
through Shani governance before execution.

Usage:
    pip install shani anthropic
    ANTHROPIC_API_KEY=your_key python example.py

Note: If ANTHROPIC_API_KEY is not set, runs in dry-run mode (Claude API not called).
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
from shani.adapters.cowork import ShaniCoworkAdapter, CoworkToolPolicy


# ─── 1. Build governance gate ─────────────────────────────────────────────────

channel = CLIApprovalChannel()

evaluator = ShaniEvaluator(
    authority_provider=StaticAuthorityProvider(max_dsal=3),
    decision_policy=DecisionPolicyProvider(
        agent_registry={
            "cowork-agent/v1": AgentIdentity(
                agent_id="cowork-agent/v1",
                granted_dsal=2,
                allowed_decision_types=frozenset(
                    [
                        "tool_call",
                        "data_access",
                        "remediation",
                        "configuration_change",
                        "agent_task",
                    ]
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


# ─── 2. Initialize Shani cowork adapter ───────────────────────────────────────

adapter = ShaniCoworkAdapter(
    gate=gate,
    proposed_by="cowork-agent/v1",
    policy={
        "bash": CoworkToolPolicy(
            decision_type=DecisionType.AGENT_TASK,
            blast_radius=BlastRadius.SIGNIFICANT,
            reversibility=False,
        ),
        "write_file": CoworkToolPolicy(
            decision_type=DecisionType.CONFIGURATION_CHANGE,
            blast_radius=BlastRadius.LIMITED,
        ),
        "read_file": CoworkToolPolicy(
            decision_type=DecisionType.DATA_ACCESS,
            blast_radius=BlastRadius.ISOLATED,
        ),
    },
)


# ─── 3. Define tool registry ──────────────────────────────────────────────────

import subprocess


def bash_tool(inp: dict) -> str:
    """Execute a shell command (high risk)."""
    cmd = inp.get("command", "")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return result.stdout or result.stderr


def read_file_tool(inp: dict) -> str:
    """Read a file (low risk)."""
    path = inp.get("path", "")
    with open(path) as f:
        return f.read()


def write_file_tool(inp: dict) -> str:
    """Write to a file (medium risk)."""
    path = inp.get("path", "")
    content = inp.get("content", "")
    with open(path, "w") as f:
        f.write(content)
    return f"Written {len(content)} bytes to {path}"


tool_registry = {
    "bash": bash_tool,
    "read_file": read_file_tool,
    "write_file": write_file_tool,
}

# Convert to Shani governance tool registry (optional: using governed_registry approach)
# governed_registry = adapter.wrap_tool_registry(tool_registry)


# ─── 4. Claude API loop (calls API if ANTHROPIC_API_KEY is set) ───────────────

ANTHROPIC_TOOLS = [
    {
        "name": "bash",
        "description": "Execute a shell command and return the output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file and return its contents.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
]


def run_cowork_loop(task: str):
    """Claude API agent loop with Shani governance."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[dry-run] ANTHROPIC_API_KEY not set. Simulating tool_use response.")
        # Dry-run simulation
        fake_tool_use = [
            {
                "type": "tool_use",
                "id": "tu_1",
                "name": "read_file",
                "input": {"path": "/etc/hostname"},
            },
        ]
        results = adapter.process_response(fake_tool_use, tool_registry)
        print(f"[dry-run] Tool results: {results}")
        return

    try:
        import anthropic
    except ImportError:
        print("anthropic package is not installed. pip install anthropic")
        return

    client = anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": task}]

    while True:
        response = client.messages.create(
            model="claude-opus-4-7-20261001",
            max_tokens=4096,
            tools=ANTHROPIC_TOOLS,
            messages=messages,
        )

        # Exit if no tool_use
        tool_use_blocks = [
            b
            for b in response.content
            if (b.get("type") if isinstance(b, dict) else getattr(b, "type", None)) == "tool_use"
        ]
        if not tool_use_blocks:
            # Final text response
            for block in response.content:
                text = (
                    block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
                )
                if text:
                    print(f"\nClaude: {text}")
            break

        # Execute tools via Shani governance
        messages.append({"role": "assistant", "content": response.content})
        tool_results = adapter.process_response(response, tool_registry)
        messages.append({"role": "user", "content": tool_results})


if __name__ == "__main__":
    run_cowork_loop("Check what's in /etc/hostname and summarize it.")
