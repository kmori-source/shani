# shani-governed-api

Governed external API skill for OpenClaw.

All external API calls are routed through the Shani Decision Governance Layer for approval before execution. No action is taken without a valid Authorized Decision Object (ADO).

## How it works

| Operation | D-SAL | Approval |
|---|---|---|
| GET (read) | 1 | Auto-approved |
| POST (write) | 2 | Human approval required |
| Shell command | 2 | Human approval required |

D-SAL is computed by Shani from the operation context (target, blast_radius, evidence). The skill does not declare its own oversight level.

## Setup

1. Start the Shani sidecar:
   ```bash
   pip install shani
   python -m shani.sidecar --port 8765
   ```

2. Set the environment variable:
   ```
   SHANI_SIDECAR_URL=http://127.0.0.1:8765
   ```

## Usage

Speak to OpenClaw naturally — the skill is invoked automatically:
- "Check the status of api.example.com" → GET → auto-approved
- "Send the results to api.example.com/reports" → POST → HITL required

## HITL approval

Operations requiring D-SAL 2 or higher are placed in a pending queue.

- `GET /pending` — list pending approvals
- `POST /decision` — approve or deny

Connect a Slack bot or Web UI to these endpoints to approve from anywhere.

## Async approval flow

```
Skill → POST /approve → { request_id }   (HITL path)
Skill → POST /collect  → { token }       (polls until decided)
Human → POST /decision → approve/deny    (from Slack / Web UI)
Skill → POST /execute  → result
```
