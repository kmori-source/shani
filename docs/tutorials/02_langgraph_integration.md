# Tutorial 02: LangGraph Integration

Add Shani governance to your existing LangGraph agent in three patterns.
No changes to your graph topology required.

---

## What you'll learn

- Pattern A: Wrap tools (zero graph changes)
- Pattern B: Wrap nodes (node-level governance)
- Pattern C: Mid-execution pause and resume
- How to read the audit log your agent produces

---

## Prerequisites

```bash
pip install "shani[langchain]"
# adds LangChain/LangGraph adapters
```

---

## Setup: Build a HITLGate

All three patterns share the same gate. Build it once.

```python
from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel

# Register your agent
agents = {
    "my-agent/v1": AgentIdentity(
        agent_id="my-agent/v1",
        granted_dsal=3,
        allowed_decision_types=frozenset([
            "remediation", "configuration_change", "network_action"
        ]),
    )
}

evaluator = ShaniEvaluator(
    authority_provider=StaticAuthorityProvider(max_dsal=3),
    decision_policy=DecisionPolicyProvider(agent_registry=agents),
)

# approval_required_at_dsal=2 means:
#   D-SAL 0-1 → auto-approved
#   D-SAL 2+  → human approval required
gate = HITLGate(
    evaluator=evaluator,
    channel=CallbackApprovalChannel(
        on_new_request=lambda req: print(f"[HITL] Approval needed: {req.to_display_dict()}")
    ),
    approval_required_at_dsal=2,
    timeout_minutes=30,
)
```

To approve programmatically (for testing):

```python
channel.approve(request_id, authority="operator@example.com", note="reviewed")
```

---

## Pattern A: Tool-level governance (zero graph changes)

Wrap your tools before passing them to the agent. Your graph stays identical.

```python
from shani.adapters.langgraph import shani_tools
from langchain_core.tools import tool

@tool
def restart_service(service_name: str) -> str:
    """Restart a named service."""
    # your implementation
    return f"Restarted {service_name}"

@tool
def update_config(key: str, value: str) -> str:
    """Update a configuration value."""
    # your implementation
    return f"Updated {key}={value}"

# Wrap tools — specify blast_radius per tool
governed = shani_tools(
    tools=[restart_service, update_config],
    gate=gate,
    proposed_by="my-agent/v1",
    policy={
        "restart_service": dict(blast_radius=BlastRadius.LIMITED),
        "update_config":   dict(blast_radius=BlastRadius.SIGNIFICANT),
    },
)

# Pass governed tools to your agent — nothing else changes
from langgraph.prebuilt import create_react_agent
agent = create_react_agent(llm, tools=governed)
```

**What changes:** Each tool call now goes through Shani before executing.
If D-SAL ≥ 2, the call blocks until a human approves.
**What doesn't change:** Your graph, your nodes, your state schema.

---

## Pattern B: Node-level governance

Wrap individual nodes that perform high-risk operations.

```python
from shani.adapters.langgraph import governed_node
from shani.schemas.decision import EvidenceItem

def isolate_host(state: dict) -> dict:
    """Your existing node function — no changes needed."""
    target = state["target"]
    # ... isolate logic ...
    return {**state, "isolated": True}

# Wrap the node
governed_isolate = governed_node(
    fn=isolate_host,
    gate=gate,
    decision_type=DecisionType.NETWORK_ACTION,
    blast_radius=BlastRadius.SIGNIFICANT,
    proposed_by="my-agent/v1",

    # Extract target from state for the proposal
    target_extractor=lambda s: s.get("target", "unknown"),

    # Extract evidence from state (the more evidence, the lower the D-SAL)
    evidence_extractor=lambda s: [
        EvidenceItem(
            source=e["source"],
            content=e["content"],
            confidence=e["confidence"]
        )
        for e in s.get("evidence", [])
    ],
)

# Use in your StateGraph as normal
from langgraph.graph import StateGraph
builder = StateGraph(dict)
builder.add_node("isolate", governed_isolate)   # drop-in replacement
# ... rest of your graph ...
```

**The ADO is stored in state** after approval:

```python
# After governed_isolate runs:
ado = state["shani_ado"]
print(f"Authorized by: {ado.authority}")
print(f"D-SAL: {ado.authorized_dsal}")

# If denied:
if state.get("shani_denied"):
    print(f"Denied: {state['shani_denied']}")
```

---

## Pattern C: Mid-execution pause and resume

For long-running nodes, register a session so humans can pause mid-flight.

```python
from shani.hitl.mid_execution.monitor import MidExecutionMonitor, ExecutionAborted

monitor = MidExecutionMonitor(
    silence_threshold_seconds=60.0,
    on_silence=lambda s: alert_ops(f"Agent silent: {s.agent_id}"),
)
monitor.start_watchdog()

# In your node:
def long_running_node(state: dict) -> dict:
    ado = state["shani_ado"]
    session_id = monitor.register(ado, agent_id="my-agent/v1")

    for step in range(10):
        # This blocks if a human has paused the session
        try:
            monitor.checkpoint(session_id)
        except ExecutionAborted as e:
            return {**state, "aborted": str(e)}

        monitor.heartbeat(session_id, f"step {step + 1}/10")
        # ... do work ...

    monitor.complete(session_id, "all steps done")
    return {**state, "done": True}
```

**Human intervention from your ops tool:**

```python
# Pause a running agent
monitor.pause(session_id, authority="alice@example.com", reason="reviewing output")

# Resume after review
monitor.resume(session_id, authority="alice@example.com")

# Abort if something looks wrong
monitor.abort(session_id, authority="alice@example.com", reason="unexpected behavior")
```

---

## Reading the audit log

Every run produces a tamper-evident audit log. Add this to your entry point:

```python
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

audit = {
    "session": str(uuid.uuid4()),
    "started_at": datetime.now(tz=timezone.utc).isoformat(),
    "actions": [],
}
audit_path = Path("audit.json")
audit_path.write_text(json.dumps(audit, indent=2))

def record(step: str, state: dict):
    """Call this after each governed node."""
    if state.get("shani_denied"):
        entry = {"step": step, "status": "DENIED", "reason": str(state["shani_denied"])}
    elif state.get("shani_ado"):
        ado = state["shani_ado"]
        entry = {
            "step":          step,
            "status":        "AUTHORIZED",
            "decision_id":   str(ado.decision_id),
            "authority":     ado.authority,
            "dsal":          ado.authorized_dsal,
            "proposal_hash": ado.proposal_hash,
            "signature":     ado.signature,
            "issued_at":     ado.issued_at.isoformat(),
        }
    else:
        return
    entry["timestamp"] = datetime.now(tz=timezone.utc).isoformat()
    audit["actions"].append(entry)
    audit_path.write_text(json.dumps(audit, indent=2))  # flush on every append
```

The log is written on every append — if your agent crashes mid-run, you still
have a complete record of everything that happened up to that point.

**Sample output:**

```json
{
  "session": "ef134ae5-f5f9-4ebb-8108-04e74b715fd8",
  "actions": [
    {
      "step": "isolate",
      "status": "DENIED",
      "reason": "Production network operations require at least 2 evidence items (current count: 1)",
      "timestamp": "2026-05-27T01:01:26.153310+00:00"
    },
    {
      "step": "mid_execution",
      "event": "paused",
      "authority": "alice@example.com",
      "detail": "reviewing step 2 output",
      "timestamp": "2026-05-27T01:01:26.506321+00:00"
    }
  ]
}
```

The denied entry tells you *why* the agent was stopped — not just *that* it was stopped.
This is the log you hand to your security team or compliance officer.

---

## Choosing a pattern

| Pattern | When to use |
|---|---|
| **A: Tool-level** | You want governance with zero graph changes. Start here. |
| **B: Node-level** | You need per-node evidence extraction or lineage tracking. |
| **C: Mid-execution** | Your nodes run for minutes and humans need to intervene mid-flight. |

Patterns can be combined. A common setup: Pattern A for most tools, Pattern B
for the highest-risk nodes, Pattern C for long-running remediation workflows.

---

## What's next

- **[Tutorial 03](03_hitl_slack.md)** — Wire up Slack approvals for production HITL
- **[Policy Reference](../POLICY_REFERENCE.md)** — Tune D-SAL thresholds and authority roles
- **[Architecture](../ARCHITECTURE.md)** — Understand the RiskPipeline and ADO structure
