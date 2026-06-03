# Shani

**Decision Governance Layer for Autonomous AI Agents**

> "Shani does not make agents smarter. It makes their actions accountable."

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Spec](https://img.shields.io/badge/spec-v0.4-green.svg)](spec/shani-v0.4.md)
[![CI](https://github.com/kmori-source/shani/actions/workflows/ci.yml/badge.svg)](https://github.com/kmori-source/shani/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/shani.svg)](https://pypi.org/project/shani/)

---

## The problem

When an autonomous agent takes an action in production, you can log what happened.
But you can't prove it was **authorized** — who approved it, under what scope, with what evidence.

Observability tools answer *"what did the agent do?"*
Shani answers *"was the agent allowed to do it — and who said so?"*

---

## How it works

Shani sits between an agent's intent and its execution.
An agent proposes a decision. Shani evaluates it against your policy.
If authorized, Shani issues a signed **ADO (Authorized Decision Object)**.
The agent may only act through a `Capability` issued from a valid ADO.

```
Agent ──DecisionProposal──► Shani ──ADO──► ExecutionBoundary ──Capability──► World
```

**No ADO → no Capability → no execution.**

Every action — authorized or denied — produces a tamper-evident audit entry:

```json
{
  "session": "ef134ae5-f5f9-4ebb-8108-04e74b715fd8",
  "scenario": "LangGraph HITL — security incident response",
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

The denied entry tells you *why* the agent was stopped, not just *that* it was stopped.
The pause entry records who intervened and when. This is the audit trail you hand to your
security team, your compliance officer, or your incident response runbook.

---

## Quick start

```bash
pip install "shani[core]"

shani check    # end-to-end ADO issuance check
shani demo     # HITL demo (auto-approve)
```

Or run the LangGraph security incident response demo:

```bash
git clone https://github.com/kmori-source/shani
cd shani && pip install -e ".[all]"

# Approve all actions automatically (CI-safe)
SHANI_HITL_AUTO=approve python examples/langgraph_hitl/scenario.py

# Deny all — see what the audit log captures when an agent is stopped
SHANI_HITL_AUTO=deny python examples/langgraph_hitl/scenario.py
cat audit_langgraph.json
```

---

## Drop-in integration — no agent logic changes

### LangGraph

```python
from shani.adapters.langgraph import shani_tools, governed_node

# Wrap tools — zero changes to your graph
governed = shani_tools(tools, gate=hitl_gate, proposed_by="agent/v1")
agent = create_react_agent(llm, tools=governed)

# Or wrap individual nodes
builder.add_node("remediate", governed_node(fn=remediate_node, gate=gate, ...))
```

### LangChain

```python
from shani.adapters.langchain import patch_langchain_tools

governed = patch_langchain_tools(tools, gate=hitl_gate, proposed_by="agent/v1")
```

### AutoGen

```python
from shani.adapters.autogen import shani_autogen_tool

governed_fn = shani_autogen_tool(
    fn=my_tool_fn,
    gate=hitl_gate,
    decision_type=DecisionType.REMEDIATION,
    blast_radius=BlastRadius.LIMITED,
    proposed_by="agent/v1",
)
```

### Generic (any agent framework)

```python
from shani.adapters.generic import governed_tool

@governed_tool(gate=hitl_gate, decision_type=DecisionType.REMEDIATION,
               blast_radius=BlastRadius.LIMITED, proposed_by="agent/v1")
def my_tool(**kwargs):
    ...
```

### OpenClaw (or any HTTP-based agent)

```bash
python examples/openclaw_integration/shani_sidecar/server.py
```

```javascript
const token = await fetch('/approve', { method: 'POST', body: JSON.stringify({...}) })
const result = await fetch('/execute', { method: 'POST', body: JSON.stringify({ token, ...}) })
```

### Chrome Extension

```python
from shani.adapters.chrome import ChromeAdapter

adapter = ChromeAdapter(gate=hitl_gate, proposed_by="chrome-extension/v1")
```

### Ollama

```bash
OLLAMA_MODEL=llama3.2 python examples/langgraph_api/demo.py
```

---

## Human-in-the-Loop

Configure which risk level requires human approval. Wire in your Slack bot or webhook.
Shani blocks execution until a human explicitly approves.

```python
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel

channel = CallbackApprovalChannel(
    on_new_request=lambda req: notify_slack(req.to_display_dict())
)
gate = HITLGate(
    evaluator=ShaniEvaluator(...),
    channel=channel,
    approval_required_at_dsal=2,   # D-SAL 2+ requires human sign-off
)

# In your Slack bot / webhook handler:
channel.approve(request_id, authority="alice@example.com", note="reviewed alert")
```

Mid-execution pause and resume are also supported — an agent already running
can be stopped and held for review without terminating the session:

```python
mid_monitor.pause(session_id, authority="alice@example.com", reason="reviewing output")
# ... review ...
mid_monitor.resume(session_id, authority="alice@example.com")
```

When denied, `DeniedDecision.to_human_summary()` returns JSON with `risk_score`,
`rules_triggered`, `evidence_flags`, and proposal snapshot —
so humans understand why the agent was stopped.

---

## Policy as Code

All governance parameters live in `policy/decision_policy.yaml`. No code changes needed:

```yaml
# What each action type requires
decision_policy:
  remediation:          1
  configuration_change: 2
  network_action:       3
  policy_update:        4   # always D-SAL 4, hardcoded rule

# What each ADO can do
capability_matrix:
  data_access:
    operations: [http_get, read_file]
  configuration_change:
    operations: [http_post, http_put, write_file]

# What counts as a high-risk environment
environment_rules:
  high_risk_keywords: [prod, production, live, customer-data, main-cluster]

# Who approves at each level
authority_roles:
  1: "SRE"
  2: "Security-Engineer"
  3: "CISO"
  4: "Board-Level"
```

---

## Risk pipeline

Effective D-SAL is computed from proposal context — **the agent does not declare its own risk level.**

```
EvidenceEvaluator    → quality score (source trust × confidence)
RiskAssessor         → RiskScore (blast_radius, reversibility, environment, evidence, intent)
RuleEngine           → hard rules (DENY / OVERRIDE before scoring)
DecisionSpaceAnalyzer→ framing detection (alternatives declared?)
DSALMapper           → risk_score → effective_dsal (configurable thresholds)
```

`risk_score` (0.0–1.0) and `D-SAL` (0–4) are separate concepts.
The threshold table in `policy.yaml` converts between them.

---

## Security guarantees

| Threat | Defense |
|---|---|
| Fake ADO | `proposal_hash` — ADO bound to exact proposal |
| Replay attack | `nonce` — one-time, persists across restarts (FileNonceStore) |
| D-SAL self-declaration | `requested_dsal` field removed — Shani computes from context |
| Delegation escalation | `max_child_dsal < authorized_dsal` (schema invariant) |
| Fan-out attack | `max_children` — bounded descendants |
| Execution drift | `exec_context` fully signed |
| Framing attack | `DecisionSpaceAnalyzer` — alternatives required for high-risk |
| Evidence fabrication | Source trust multipliers — SELF_REPORTED = 0.35× |

---

## ADO structure (v5)

```
AuthorizedDecisionObject
 ├── decision_id        identity
 ├── proposal_hash      integrity: SHA-256 of exact proposal
 ├── signature          HMAC-SHA256 of canonical payload (all fields)
 ├── authority          who approved (from authority_provider)
 ├── authorized_dsal    governance level granted
 ├── delegation_rules   escalation + fan-out prevention
 ├── nonce              replay prevention (one-time, 32 bytes)
 ├── issued_at / expires_at
 └── exec_context       signed execution metadata
```

Every field is covered by the signature. Any mutation breaks verification.

---

## Installation

```bash
pip install shani                        # core (stdlib only, no dependencies)
pip install "shani[core]"               # + pydantic + pyyaml (recommended)
pip install "shani[langchain]"          # + LangChain/LangGraph adapters
pip install "shani[all]"                # everything
```

Optional dependencies for production:

```bash
pip install "pydantic>=2.5" pyyaml   # schema validation + policy files
pip install cryptography              # Ed25519 signatures
pip install langgraph langchain-core  # LangGraph integration
pip install langchain-ollama          # Ollama support
```

A pydantic shim (`shani/_compat.py`) is included — everything runs without it.

---

## Running tests

```bash
pip install -e ".[dev]"

shani check                # quick ADO issuance + verification
shani demo                 # HITL demo (auto-approve)
pytest                     # full test suite

pytest tests/unit/
pytest tests/security/
pytest tests/security/test_signature_coverage.py   # 19 field mutations
pytest tests/security/test_dsal_calculator.py      # D-SAL context computation
pytest tests/security/test_risk_pipeline.py        # 4-component risk pipeline
```

---

## Examples

| Directory | Description |
|---|---|
| `examples/langgraph_hitl/` | LangGraph security incident response with full audit log |
| `examples/hitl_approval/` | Human-in-the-loop approval flow |
| `examples/remediation/` | Basic proposal → ADO → execution |
| `examples/delegation/` | Orchestrator → specialist with escalation blocking |
| `examples/dis_violation/` | Replay attack → VIOLATED state → manual reset |
| `examples/firewall_chain/` | Risk levels and RuleEngine DENY/OVERRIDE |
| `examples/langgraph_api/` | LangGraph + Ollama integration |
| `examples/openclaw_integration/` | HTTP sidecar for non-Python agents |
| `examples/agent_integration/` | Generic agent integration |
| `examples/chrome_extension/` | Chrome extension adapter |

---

## Documents

### Tutorials

- [`docs/tutorials/01_quickstart.md`](docs/tutorials/01_quickstart.md) — Get started in 5 minutes
- [`docs/tutorials/02_langgraph_integration.md`](docs/tutorials/02_langgraph_integration.md) — Add Shani to your LangGraph agent (3 patterns)
- [`docs/tutorials/03_hitl_slack.md`](docs/tutorials/03_hitl_slack.md) — Wire up Slack approvals for production HITL

### Reference

- [`spec/shani-v0.4.md`](spec/shani-v0.4.md) — Normative specification (takes precedence over code)
- [`spec/threat-model.md`](spec/threat-model.md) — Threats and mitigations (18 threats)
- [`spec/canonicalization.md`](spec/canonicalization.md) — Canonical serialization for signatures
- [`spec/ado-schema.json`](spec/ado-schema.json) — Normative JSON Schema for ADO
- [`rfcs/RFC-0001-posture-engine.md`](rfcs/RFC-0001-posture-engine.md) — PostureEngine design
- [`rfcs/RFC-0002-propagated-constraints.md`](rfcs/RFC-0002-propagated-constraints.md) — Cross-org constraints
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System design and data flow
- [`docs/POLICY_REFERENCE.md`](docs/POLICY_REFERENCE.md) — Complete policy.yaml reference

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
