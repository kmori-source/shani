# Tutorial 01: Quickstart

Get Shani running in under 5 minutes. No configuration required.

---

## What you'll learn

- How to install Shani
- What `shani check` verifies and why it matters
- What `shani demo` shows you about the HITL approval flow

---

## Prerequisites

- Python 3.11+
- pip

---

## Step 1: Install

```bash
pip install "shani[core]"
```

`[core]` adds `pydantic` and `pyyaml`, which are required for policy validation
and schema enforcement. The base `shani` package runs on stdlib only — useful
for dependency-constrained environments.

---

## Step 2: Run the end-to-end check

```bash
shani check
```

This command runs a complete authorization cycle:

1. Constructs a `DecisionProposal` targeting a production host
2. Evaluates it through the full `RiskPipeline`
3. Issues a signed `ADO` (Authorized Decision Object)
4. Verifies the signature with `verify_binding()`
5. Consumes the nonce with `register_executed()`
6. Attempts replay — and confirms it is blocked

**Expected output:**

```
════════════════════════════════════════════════════════════
  shani check — Quick End-to-End Verification
════════════════════════════════════════════════════════════
  ✓ ADO issued
    decision_id    : 39fa589f…
    proposal_hash  : 941a28535ad78a10…
    authority      : SecOps-Lead
    authorized_dsal: 2
    nonce          : f79a18feaa60d341…
    issued_at      : 23:47:31 UTC
    expires_at     : 23:52:31 UTC
    signature      : 3iXC19M6OgKqNaMV…
  ✓ verify_binding: OK
  ✓ register_executed: nonce consumed
  REPLAY DETECTED | decision=39fa589f nonce=f79a18feaa60d341
  ✓ replay blocked: verify_binding after execution = False

  ✓ End-to-end check passed.
```

**What each field means:**

| Field | What it guarantees |
|---|---|
| `proposal_hash` | ADO is bound to the exact proposal. A fake ADO cannot be substituted. |
| `signature` | Every field is covered. Any mutation breaks verification. |
| `authority` | Who approved this action. Comes from `authority_roles` in `policy.yaml`. |
| `authorized_dsal` | Governance level actually applied (computed by Shani, not declared by agent). |
| `nonce` | One-time token. Consumed on execution. Replay is cryptographically impossible. |

---

## Step 3: Run the HITL demo

```bash
shani demo
```

This shows three cases side by side:

```
  D-SAL 1 (dev, isolated)    : AUTHORIZED  dsal=1  authority=SOC-Analyst
  D-SAL 2 (prod, HITL)       : AUTHORIZED  dsal=2  authority=SecOps-Lead
  CRITICAL+irreversible (deny): DENIED
```

**What each case demonstrates:**

**D-SAL 1 — auto-approved.**
The proposal targets a dev host with isolated blast radius. Risk is low enough
that no human approval is needed. The action is logged but proceeds automatically.

**D-SAL 2 — HITL required.**
The proposal targets a production host. Shani computes the risk as D-SAL 2,
which exceeds the HITL threshold. A human (in this demo: auto-approved) must
explicitly sign off before the ADO is issued.

**CRITICAL + irreversible — hard deny.**
The `critical_irreversible_floor` rule fires before scoring even completes.
No human can override this; it is a hard rule in the `RuleEngine`.

---

## Step 4: Run the LangGraph demo

```bash
git clone https://github.com/kmori-source/shani
cd shani
pip install -e ".[all]"

SHANI_HITL_AUTO=approve python examples/langgraph_hitl/scenario.py
```

After it runs:

```bash
cat audit_langgraph.json
```

You'll see a complete, tamper-evident audit trail of every action — authorized,
denied, and mid-execution events — written to disk in real time.

The `isolate` step will be denied:

```json
{
  "step": "isolate",
  "status": "DENIED",
  "reason": "Production network operations require at least 2 evidence items (current count: 1)",
  "timestamp": "2026-05-27T01:01:26.153310+00:00"
}
```

This is Shani working correctly. The agent proposed an action without sufficient
evidence. The policy blocked it. The reason is recorded.

---

## What's next

- **[Tutorial 02](02_langgraph_integration.md)** — Add Shani to your own LangGraph agent
- **[Tutorial 03](03_hitl_slack.md)** — Wire up Slack approvals for production HITL
- **[Policy Reference](../POLICY_REFERENCE.md)** — Customize `policy.yaml` for your organization
