# Shani Architecture

## Overview

Shani is a **Decision Governance Layer** that sits between an AI agent's intent and its execution. It does not replace authentication, authorization, or network security. It governs **decisions** — discrete, purposeful actions that agents propose and must justify.

```
Agent                    Shani                     World
  │                        │                          │
  │── DecisionProposal ──► │                          │
  │                        │  RiskPipeline            │
  │                        │  ├─ EvidenceEvaluator    │
  │                        │  ├─ RiskAssessor         │
  │                        │  ├─ RuleEngine           │
  │                        │  ├─ DecisionSpaceAnalyzer│
  │                        │  └─ DSALMapper           │
  │                        │                          │
  │                        │  [HITL if D-SAL ≥ threshold]
  │                        │                          │
  │◄── ADO ───────────────│                          │
  │    (signed, one-time)  │                          │
  │                        │                          │
  │  ExecutionBoundary     │                          │
  │  issue_capability(ado) │                          │
  │                        │                          │
  │── cap.http_get() ─────────────────────────────── ►│
  │                        │                          │
  │── register_executed()─►│  (nonce consumed)        │
```

---

## Components

### DecisionProposal

The only input Shani accepts from an agent. The agent describes what it wants to do, why, and with what evidence. The agent does NOT declare its own oversight level — that is Shani's job.

### RiskPipeline

Four independent components evaluated in sequence:

```
EvidenceEvaluator    → quality_score (0.0–1.0)
      ↓
RiskAssessor         → RiskScore (aggregate + dimensions)
      ↓
RuleEngine           → DENY / OVERRIDE / PASS
      ↓
DecisionSpaceAnalyzer→ framing_risk_score
      ↓
DSALMapper           → effective_dsal
```

**Key design decision:** `risk_score` and `D-SAL` are separate concepts. risk_score measures reality (how dangerous is this). D-SAL measures governance (who must approve). The DSALMapper's threshold table is the configurable policy that connects them.

### Policy

All governance parameters live in `policy/decision_policy.yaml`. Nothing is hardcoded:

```yaml
decision_policy:       # DecisionType → base D-SAL
capability_matrix:     # DecisionType → allowed operations
environment_rules:     # high_risk_keywords list
authority_roles:       # D-SAL → human role name
agent_registry:        # agent ID → granted D-SAL + allowed types
```

### ADO (Authorized Decision Object)

A cryptographically signed token. Every security-relevant field is covered by the signature. Mutation of any field breaks verification.

```
proposal_hash    → binds ADO to exact proposal (fake ADO detection)
signature        → HMAC-SHA256 of all fields except signature itself
nonce            → one-time token (replay prevention)
delegation_rules → max_child_dsal < authorized_dsal (escalation prevention)
exec_context     → signed (execution drift prevention)
```

### ExecutionBoundary

The only place where ADOs become executable Capabilities. No ADO → no Capability → no execution.

```python
# The only way to get a Capability
cap = boundary.issue_capability(ado, proposal)

# The only way to execute
result = cap.http_get(url)    # or http_post, read_file, etc.
```

The allowed operations per DecisionType are defined in `policy.yaml capability_matrix`, not in code.

### NonceStore

Persistent replay prevention. A nonce consumed once is never accepted again, even after process restart.

```
InMemoryNonceStore  → development/testing
FileNonceStore      → production (append-only JSONL)
Custom              → implement NonceStore protocol (Redis, PostgreSQL, etc.)
```

### HITL Gate

Wraps the evaluator and inserts human approval when `effective_dsal >= threshold`.

```python
gate = HITLGate(
    evaluator=ShaniEvaluator(...),
    channel=CallbackApprovalChannel(),  # or Slack, webhook, CLI
    approval_required_at_dsal=2,
)
```

The authority role name displayed to humans comes from `authority_provider.resolve_authority()` — not from a hardcoded dict.

### DIS (Decision Integrity State)

Tracks system integrity. If integrity is VIOLATED, all proposals are denied until a named human resets it with justification.

---

## Data Flow

### Happy Path

```
1. Agent constructs DecisionProposal (no requested_dsal)
2. RiskPipeline computes effective_dsal from context
3. If effective_dsal >= HITL threshold → wait for human
4. Agent authorization check (granted_dsal >= effective_dsal)
5. ADO issued (signed, nonce set)
6. Agent calls ExecutionBoundary.issue_capability(ado, proposal)
7. Boundary verifies: signature, proposal_hash, nonce not consumed, not expired
8. Capability issued with allowed_operations from capability_matrix
9. Agent calls cap.http_get(url) or similar
10. register_executed(ado) consumes nonce
```

### Denial Path

```
At any step, failure produces DeniedDecision with:
  - reason (human-readable)
  - pipeline_result (risk_score, rules_triggered, evidence_flags)
  - proposal snapshot
  - to_human_summary() → JSON for HITL notification
```

---

## Integration Patterns

### Pattern A: Tool-level (zero graph changes)

```python
governed_tools = shani_tools(raw_tools, gate=hitl_gate, proposed_by="agent/v1")
agent = create_react_agent(llm, tools=governed_tools)
```

### Pattern B: Node-level (LangGraph)

```python
builder.add_node("isolate", governed_node(fn=isolate_node, gate=gate, ...))
```

### Pattern C: Sidecar (OpenClaw, any framework)

```
OpenClaw Skill ──POST /approve──► Shani Sidecar ──► token
OpenClaw Skill ──POST /execute──► Shani Sidecar ──► result
```

---

## File Structure

```
shani/
├── schemas/
│   ├── decision.py     DecisionProposal, ADO v5, DelegationRules, ExecContext
│   └── state.py        DIS, DSAL state machine
├── core/
│   └── evaluator.py    ShaniEvaluator — orchestrates pipeline
├── risk/
│   ├── assessor.py     RiskAssessor — multi-dimensional risk scoring
│   ├── dsal_mapper.py  DSALMapper — risk_score → D-SAL
│   ├── rules.py        RuleEngine — hard rules
│   ├── evidence.py     EvidenceEvaluator — epistemic quality
│   ├── decision_space.py DecisionSpaceAnalyzer — framing detection
│   └── pipeline.py     RiskPipeline — orchestrates all four
├── authority/
│   ├── policy.py       DecisionPolicyProvider, CapabilityMatrix, AgentIdentity
│   ├── dsal_calculator.py DSALCalculator (legacy; pipeline replaces this)
│   └── provider.py     YAMLAuthorityProvider, StaticAuthorityProvider
├── boundary/
│   ├── capability.py   ExecutionBoundary, Capability
│   └── hook.py         DecisionBoundary, DecisionFirewall, DenialContext
├── hitl/
│   ├── approval/
│   │   ├── gate.py     HITLGate
│   │   └── request.py  ApprovalRequest state machine
│   ├── channel/
│   │   └── channels.py CLI, Callback, Webhook, Slack channels
│   └── mid_execution/
│       └── monitor.py  MidExecutionMonitor (pause/resume/abort)
├── security/
│   └── replay_store.py InMemoryNonceStore, FileNonceStore
├── integrity/
│   └── monitor.py      DISIntegrityMonitor
├── adapters/
│   ├── langchain/      ShaniLangChainTool, patch_langchain_tools
│   ├── langgraph/      shani_tools, governed_node, ShaniLangGraph
│   └── autogen/        shani_autogen_tool, patch_autogen_agent
└── _compat.py          pydantic shim (stdlib-only fallback)

policy/
└── decision_policy.yaml  Single Source of Truth for all policy

spec/
├── shani-v0.4.md        Normative specification (takes precedence over code)
├── ado-schema.json      Normative JSON Schema for AuthorizedDecisionObject
├── proposal-schema.json Normative JSON Schema for DecisionProposal
├── posture-schema.json  Normative JSON Schema for UserPosture
├── canonicalization.md  Canonical serialization format for signatures
├── threat-model.md      Threat catalog and residual risk analysis
└── interoperability/    Cross-implementation conformance profiles
```
