---
name: shani-governance
description: >-
  Shani Governance: MANDATORY decision authorization layer for high-risk
  operations. You MUST call Shani BEFORE executing any action that modifies
  files, runs commands, changes configuration, accesses sensitive data, or
  performs network operations on production systems. Shani evaluates the
  risk, obtains human approval if required, and issues a signed authorization
  token. Do NOT execute high-risk actions without a valid Shani ADO.
compatibility: Requires Shani sidecar running on 172.17.0.1:8765 (start with `python start_sidecar.py`)
metadata:
  author: kmori
  version: "0.1.0"
---

# Shani Governance Layer

Shani sits between your intent and execution. Before taking any high-risk
action, you must submit a DecisionProposal to Shani and receive an
Authorized Decision Object (ADO). No ADO → no execution.

## When to use Shani

Use Shani BEFORE any of the following:

- Writing, modifying, or deleting files in production directories
- Running shell commands that affect system state (`rm`, `mv`, `chmod`, `systemctl`, etc.)
- Making HTTP POST/PUT/DELETE requests to external APIs
- Accessing credentials, secrets, or sensitive configuration
- Isolating or restarting services
- Any operation on hosts containing: `prod`, `production`, `live`, `main`

You do NOT need Shani for:
- Reading files (low-risk)
- HTTP GET requests (read-only)
- Local development operations

## How to submit a DecisionProposal

```bash
curl -s -X POST http://172.17.0.1:8765/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "decision_type": "<TYPE>",
    "proposed_by": "nanoclaw-agent/v1",
    "description": "<what you want to do and why>",
    "target": "<target resource>",
    "scope": {"asset_ids": ["<target>"]},
    "evidence": [
      {
        "source": "nanoclaw-agent",
        "content": "<why this action is necessary>",
        "confidence": 0.85
      }
    ],
    "confidence": 0.85,
    "reversibility": <true|false>,
    "blast_radius": "<isolated|limited|significant|critical>",
    "expires_at": "<ISO8601 timestamp 10 minutes from now>"
  }'
```

## Decision types

| Action | decision_type | blast_radius |
|--------|--------------|--------------|
| Read files / HTTP GET | `data_access` | `isolated` |
| Write files / HTTP POST | `configuration_change` | `limited` |
| Run commands | `remediation` | `significant` |
| Network isolation / firewall | `network_action` | `significant` |
| Delete files / destructive ops | `remediation` | `critical` |

## Reading the response

**Authorized (proceed):**
```json
{"type": "ado", "data": {"decision_id": "...", "authority": "SOC-Analyst", "authorized_dsal": 1, ...}}
```
→ You may proceed with the action. Record the `decision_id` for the audit log.

**Denied (do not proceed):**
```json
{"type": "denied", "reason": "Production network operations require at least 2 evidence items"}
```
→ Do NOT execute the action. Explain the denial to the user and ask if they
want to provide additional evidence or escalate.

**HITL pending (waiting for human approval):**
The request will block until a human approves or denies via the configured
channel (Slack, CLI, webhook). Wait for the response before proceeding.

## After execution

Register completion so the nonce is consumed and replay is prevented:

```bash
curl -s -X POST http://172.17.0.1:8765/v1/register_executed \
  -H "Content-Type: application/json" \
  -d '{
    "ado": <full ADO object from evaluate response>,
    "agent_id": "nanoclaw-agent/v1"
  }'
```

## Example: before writing a config file

```bash
# Step 1: Submit proposal
RESPONSE=$(curl -s -X POST http://172.17.0.1:8765/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "decision_type": "configuration_change",
    "proposed_by": "nanoclaw-agent/v1",
    "description": "Update nginx config to increase worker_processes",
    "target": "/etc/nginx/nginx.conf",
    "scope": {"asset_ids": ["/etc/nginx/nginx.conf"]},
    "evidence": [
      {
        "source": "nanoclaw-agent",
        "content": "User requested performance tuning for high traffic",
        "confidence": 0.9
      }
    ],
    "confidence": 0.9,
    "reversibility": true,
    "blast_radius": "limited",
    "expires_at": "2026-12-31T00:00:00Z"
  }')

# Step 2: Check result
TYPE=$(echo $RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['type'])")

if [ "$TYPE" = "ado" ]; then
  # Step 3: Execute the action
  echo "worker_processes auto;" >> /etc/nginx/nginx.conf

  # Step 4: Register completion
  curl -s -X POST http://172.17.0.1:8765/v1/register_executed \
    -H "Content-Type: application/json" \
    -d "{\"ado\": $(echo $RESPONSE | python3 -c \"import sys,json; print(json.dumps(json.load(sys.stdin)['data']))\"), \"agent_id\": \"nanoclaw-agent/v1\"}"
else
  REASON=$(echo $RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['reason'])")
  echo "Action denied by Shani: $REASON"
fi
```

## Health check

```bash
curl -s http://172.17.0.1:8765/healthz
# → {"status": "ok"}
```

If the sidecar is not running, start it:
```bash
python start_sidecar.py
```

## Rules

- **Never** execute high-risk actions without a valid ADO from Shani.
- **Always** check the response type before proceeding (`ado` vs `denied`).
- **Always** call `register_executed` after completing an authorized action.
- **Never** retry a denied action without providing additional evidence.
- If Shani is unreachable, halt and notify the user — do not bypass governance.
