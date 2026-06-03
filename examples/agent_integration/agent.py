"""
examples/agent_integration/agent.py

AI Agent + Shani — complete integration example

Self-contained. Works without the OpenAI/Anthropic SDK.
For production: install an SDK and replace llm_call().

Structure:
    ┌─────────────────────────────────────────────┐
    │  Agent Loop (LLM → tool call → LLM → ...)  │
    │                                             │
    │  tools = [read_file, write_file,            │
    │           run_command, call_api]            │
    │                                             │
    │  ↓ wrap all with shani_tools() (one line)         │
    │                                             │
    │  governed_tools = [                         │
    │    ShaniLangChainTool(read_file, dsal=1),   │
    │    ShaniLangChainTool(write_file, dsal=2),  │
    │    ShaniLangChainTool(run_command, dsal=2), │
    │    ShaniLangChainTool(call_api, dsal=1),    │
    │  ]                                          │
    └─────────────────────────────────────────────┘
              ↓ tool calls with D-SAL ≥ 2
    ┌─────────────────────────────────────────────┐
    │  HITLGate                                   │
    │  ├ evaluate(proposal)                       │
    │  ├ CallbackApprovalChannel                  │
    │  │   → awaiting approval (auto-approve in background thread)        │
    │  └ issue ADO → verify_binding → execute         │
    └─────────────────────────────────────────────┘

Usage:
    python agent.py                # interactive mode
    python agent.py --auto         # auto-approve (for CI)
    python agent.py --deny         # rejection test
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time

# ── Shani bootstrap (pydantic shim if needed) ──────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location("_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"))
    _mod = _iu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    _shim.BaseModel = _mod.BaseModel; _shim.Field = _mod.Field
    _shim.field_validator = _mod.field_validator
    _shim.model_validator = _mod.model_validator
    sys.modules["pydantic"] = _shim

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="shani")

from datetime import datetime, timedelta, timezone

from shani import (
    ShaniEvaluator, StaticAuthorityProvider,
    DecisionType, BlastRadius,
)
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel, CLIApprovalChannel
from shani.schemas.decision import DecisionScope, EvidenceItem


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Define existing tools (your code; has no knowledge of Shani)
# ─────────────────────────────────────────────────────────────────────────────

class Tool:
    """Minimal Tool interface matching LangChain BaseTool shape."""
    def __init__(self, name: str, description: str, fn):
        self.name = name
        self.description = description
        self._fn = fn
    def run(self, inp: str) -> str:
        return self._fn(inp)


def _read_file(path: str) -> str:
    """Read a file."""
    try:
        return open(path).read()[:500]
    except Exception as e:
        return f"Error: {e}"


def _write_file(inp: str) -> str:
    """Write a file in path:content format."""
    try:
        path, _, content = inp.partition(":")
        with open(path.strip(), "w") as f:
            f.write(content.strip())
        return f"Written: {path.strip()}"
    except Exception as e:
        return f"Error: {e}"


def _run_command(cmd: str) -> str:
    """Execute a shell command."""
    import subprocess
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout or result.stderr
    except Exception as e:
        return f"Error: {e}"


def _call_api(url: str) -> str:
    """Call an external API (simulation)."""
    return f"[API] GET {url} → 200 OK (simulated)"


# Four raw tools (no knowledge of Shani)
raw_tools = [
    Tool("read_file",    "Read file contents",          _read_file),
    Tool("write_file",   "Write to a file",             _write_file),
    Tool("run_command",  "Execute a shell command",     _run_command),
    Tool("call_api",     "Call an external API",        _call_api),
]


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Set up Shani (infrastructure config; agent code unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def build_shani(channel) -> HITLGate:
    """Build the Shani evaluator + HITL gate."""

    # agent permission definitions
    agents = {
        "my-agent/v1": AgentIdentity(
            agent_id="my-agent/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset([
                "remediation",
                "configuration_change",
                "data_access",
                "network_action",
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
        approval_required_at_dsal=2,   # D-SAL 2+ requires human approval
        timeout_minutes=5,
    )


def wrap_tools(gate: HITLGate) -> list:
    """
    Wrap existing tools with Shani.
    The tools themselves are not modified. Only policy is defined here.
    """
    from shani.adapters.langchain.adapter import ShaniLangChainTool

    # per-tool policy definitions
    policy = {
        "read_file": dict(
            decision_type=DecisionType.DATA_ACCESS,
            blast_radius=BlastRadius.ISOLATED,
        ),
        "write_file": dict(
            decision_type=DecisionType.CONFIGURATION_CHANGE,
            blast_radius=BlastRadius.LIMITED,
        ),
        "run_command": dict(
            decision_type=DecisionType.REMEDIATION,
            blast_radius=BlastRadius.SIGNIFICANT,
        ),
        "call_api": dict(
            decision_type=DecisionType.DATA_ACCESS,
            blast_radius=BlastRadius.LIMITED,
        ),
    }

    governed = []
    for tool in raw_tools:
        p = policy[tool.name]
        # D-SAL 2+ requires evidence. Auto-generate evidence from tool input.
        # auto-generate evidence for all ops (source=agent-observation = AGENT_DERIVED trust)
        evidence_ext = lambda inp, n=tool.name: [
            EvidenceItem(
                source="agent-observation",
                content=f"Agent invoked {n} with input: {inp[:80]}",
                confidence=0.80,
            )
        ]
        governed.append(ShaniLangChainTool(
            tool=tool,
            gate=gate,
            proposed_by="my-agent/v1",
            target_extractor=lambda inp, n=tool.name: f"{n}:{inp[:40]}",
            evidence_extractor=evidence_ext,
            **p,
        ))

    return governed


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Agent loop (the LLM part)
# For a real LLM, just replace llm_call()
# ─────────────────────────────────────────────────────────────────────────────

def llm_call(task: str, tool_results: list[dict]) -> dict:
    """
    Mock LLM call.
    In production, replace with:

    ── OpenAI ──────────────────────────────────────────
    from openai import OpenAI
    client = OpenAI()

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": task}],
        tools=[{
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": {"type": "object",
                               "properties": {"input": {"type": "string"}}}
            }
        } for t in governed_tools],
    )
    msg = response.choices[0].message
    if msg.tool_calls:
        call = msg.tool_calls[0]
        return {"tool": call.function.name,
                "input": json.loads(call.function.arguments)["input"]}
    return {"done": True, "answer": msg.content}

    ── Anthropic ───────────────────────────────────────
    import anthropic
    client = anthropic.Anthropic()

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        tools=[{
            "name": t.name,
            "description": t.description,
            "input_schema": {"type": "object",
                             "properties": {"input": {"type": "string"}},
                             "required": ["input"]}
        } for t in governed_tools],
        messages=[{"role": "user", "content": task}],
    )
    for block in response.content:
        if block.type == "tool_use":
            return {"tool": block.name, "input": block.input["input"]}
    return {"done": True, "answer": response.content[0].text}
    """

    # Mock: returns a scenario of sequential tool calls based on the task
    steps = {
        "read": [
            {"tool": "read_file",   "input": "/etc/hostname"},
            {"tool": "call_api",    "input": "https://api.example.com/status"},
            {"done": True, "answer": "File and API check complete."},
        ],
        "write": [
            {"tool": "read_file",   "input": "/tmp/config.txt"},
            {"tool": "write_file",  "input": "/tmp/config.txt:updated=true"},
            {"done": True, "answer": "Configuration file updated."},
        ],
        "command": [
            {"tool": "read_file",   "input": "/tmp/log.txt"},
            {"tool": "run_command", "input": "echo 'task done' >> /tmp/log.txt"},
            {"done": True, "answer": "Command executed."},
        ],
    }

    # determine which scenario to run
    for key in steps:
        if key in task.lower():
            scenario = steps[key]
            idx = len(tool_results)
            if idx < len(scenario):
                return scenario[idx]
            return scenario[-1]

    # default
    return {"done": True, "answer": "Task complete."}


def run_agent(task: str, governed_tools: list) -> str:
    """
    Main agent loop.
    LLM directs tool calls → Shani filters them → results returned to LLM.
    """
    print(f"\n  Task: {task}")
    print(f"  {'─' * 50}")

    tool_map = {t.name: t for t in governed_tools}
    tool_results = []
    max_steps = 10

    for step in range(max_steps):
        # ask LLM for next action
        action = llm_call(task, tool_results)

        if action.get("done"):
            return action.get("answer", "Done")

        tool_name = action["tool"]
        tool_input = action["input"]

        print(f"\n  Step {step + 1}: LLM requests → {tool_name}({tool_input!r})")

        tool = tool_map.get(tool_name)
        if not tool:
            tool_results.append({"tool": tool_name, "result": "Error: tool not found"})
            continue

        # Shani intervenes here
        # tool.run() runs evaluate() → HITL → verify → execute
        try:
            result = tool.run(tool_input)
            print(f"  ✓ Execution complete: {result[:60]}")
            tool_results.append({"tool": tool_name, "result": result})
        except PermissionError as e:
            # Shani denied
            print(f"  ✗ Shani denied: {e}")
            tool_results.append({"tool": tool_name, "result": f"denied: {e}"})
            break

    return "Agent loop complete"


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Run
# ─────────────────────────────────────────────────────────────────────────────

def auto_responder(channel: CallbackApprovalChannel, action: str, delay: float = 0.2):
    """Thread that auto-approves or auto-denies in the background."""
    def loop():
        seen = set()
        for _ in range(60):
            time.sleep(delay)
            for req in channel.get_pending():
                if req.request_id in seen:
                    continue
                seen.add(req.request_id)
                if action == "approve":
                    channel.approve(req.request_id, "auto-operator", "auto-approve")
                    print(f"\n  [HITL] ✓ Approved: {req.decision_type} on {req.target}")
                else:
                    channel.deny(req.request_id, "auto-operator", "auto-denied")
                    print(f"\n  [HITL] ✗ Denied: {req.decision_type} on {req.target}")
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def main():
    parser = argparse.ArgumentParser(description="AI Agent + Shani integration example")
    parser.add_argument("--auto",   action="store_true", help="auto-approve mode")
    parser.add_argument("--deny",   action="store_true", help="auto-deny mode")
    parser.add_argument("--cli",    action="store_true", help="interactive CLI mode")
    args = parser.parse_args()

    print("=" * 55)
    print("  AI Agent + Shani Integration Demo")
    print("=" * 55)

    # build channel and gate
    if args.cli:
        channel = CLIApprovalChannel(operator_name="operator")
        gate = build_shani(channel)
        print("  Mode: interactive CLI (approval prompts will appear)\n")
    else:
        channel = CallbackApprovalChannel()
        gate = build_shani(channel)
        action = "deny" if args.deny else "approve"
        auto_responder(channel, action)
        print(f"  Mode: auto-{'deny' if args.deny else 'approve'}\n")

    # wrap tools (this single step puts all tools under Shani governance)
    governed_tools = wrap_tools(gate)

    print(f"  Wrapped tools ({len(governed_tools)}):")
    for t in governed_tools:
        dsal = "D-SAL 1 (auto)" if "DATA_ACCESS" in t.description or "NETWORK" in t.description else "D-SAL 2 (HITL required)"
        # get dsal from policy
        print(f"    • {t.name:<14} blast={t._blast_radius.value}")

    # run tasks
    tasks = []
    if args.deny:
        tasks = ["write please update the configuration file"]
    else:
        tasks = [
            "read please check the status of files and the API",
            "write please update the configuration file",
            "command please log the command execution result",
        ]

    for task in tasks:
        print(f"\n{'═' * 55}")
        answer = run_agent(task, governed_tools)
        print(f"\n  Agent response: {answer}")
        time.sleep(0.3)

    print(f"\n{'═' * 55}")
    print("  Done.")
    print()
    print("  For production, just replace llm_call():")
    print("    from openai import OpenAI")
    print("    # or")
    print("    import anthropic")
    print("  The tool and Shani configuration can be used as-is.")


if __name__ == "__main__":
    main()
