# Shani × nanoclaw — Sidecar Integration

Shani governs nanoclaw agent tool calls via a Python HTTP sidecar and a
SKILL.md that instructs Claude to submit a DecisionProposal before any
high-risk operation. No TypeScript code changes required.

---

## How it works

```
nanoclaw container
    │
    │  Claude reads SKILL.md:
    │  "Before high-risk ops, POST to http://172.17.0.1:8765/v1/evaluate"
    │
    ▼
Shani sidecar (Python, host network)
    │
    ├─ RiskPipeline → effective_dsal
    ├─ HITL gate (if dsal ≥ threshold) → human approval
    └─ ADO issued (signed, tamper-evident)
    │
    ▼
Claude receives ADO → proceeds with action
    │
    └─ POST /v1/register_executed → nonce consumed, audit complete
```

Every action — authorized or denied — produces a tamper-evident audit
entry with `proposal_hash` and `signature`.

---

## Setup

### 1. Install Shani

```bash
pip install "shani[core]"
# or from source:
pip install -e ".[all]"
```

### 2. Start the sidecar

```bash
# Auto-approve all HITL requests (for testing)
SHANI_HITL_AUTO=approve python examples/nanoclaw_sidecar/start_sidecar.py

# Manual approval mode (production)
python examples/nanoclaw_sidecar/start_sidecar.py
```

Sidecar listens on `0.0.0.0:8765`. nanoclaw containers reach it via
`172.17.0.1:8765` (Docker host gateway).

Verify:
```bash
curl http://localhost:8765/healthz
# → {"status": "ok"}
```

### 3. Install the SKILL.md into nanoclaw

```bash
mkdir -p /path/to/nanoclaw/container/skills/shani-governance
cp container/skills/shani-governance/SKILL.md \
   /path/to/nanoclaw/container/skills/shani-governance/SKILL.md
```

nanoclaw picks up skills automatically when `container.json` has
`"skills": "all"`.

### 4. Verify the fragment is loaded

After nanoclaw restarts, check that the skill fragment appears:

```bash
grep -i "shani" /path/to/nanoclaw/groups/<your-group>/CLAUDE.md
```

If not, add it manually:

```bash
# Copy fragment
cp container/skills/shani-governance/SKILL.md \
   /path/to/nanoclaw/groups/<group>/.claude-fragments/skill-shani-governance.md

# Register in CLAUDE.md
echo "@./.claude-fragments/skill-shani-governance.md" >> \
   /path/to/nanoclaw/groups/<group>/CLAUDE.md
```

---

## Test the integration

With the sidecar running in auto-approve mode:

```bash
# In your nanoclaw directory
pnpm run chat "Isolate host:prod-db-12. \
  Evidence: EDR detected lateral movement (confidence 0.93), \
  SIEM detected anomalous outbound traffic (confidence 0.88)"
```

You should see in the sidecar terminal:

```
[HITL] network_action → host:prod-db-12  authority=Org-Policy  dsal=3
[HITL] ✓ Auto-approved: <request_id>
```

And Claude will respond with the Decision ID and next steps:

```
Shani approval obtained.
Decision ID: 2b2b8e5a  Authority: Org-Policy  DSAL: 3
```

---

## Production setup

For production, remove `SHANI_HITL_AUTO` and wire in a real approval
channel (Slack, webhook, etc.). See
[Tutorial 03](../../docs/tutorials/03_hitl_slack.md) for Slack integration.

Also switch to `FileNonceStore` for persistence across restarts:

```python
from shani.security.replay_store import FileNonceStore

evaluator = ShaniEvaluator(
    ...
    nonce_store=FileNonceStore("shani_nonces.jsonl"),
)
```

---

## Files

```
examples/nanoclaw_sidecar/
├── start_sidecar.py          — sidecar entry point
└── README.md                 — this file

container/skills/shani-governance/
└── SKILL.md                  — nanoclaw skill (instructs Claude to use Shani)
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check |
| `POST` | `/v1/evaluate` | Submit DecisionProposal → ADO or DeniedDecision |
| `POST` | `/v1/verify_binding` | Verify ADO binding |
| `POST` | `/v1/register_executed` | Consume nonce after execution |

---

## References

- [Shani SKILL.md](../../container/skills/shani-governance/SKILL.md)
- [Tutorial 02 — LangGraph integration](../../docs/tutorials/02_langgraph_integration.md)
- [Tutorial 03 — Slack HITL](../../docs/tutorials/03_hitl_slack.md)
- [Architecture](../../docs/ARCHITECTURE.md)
