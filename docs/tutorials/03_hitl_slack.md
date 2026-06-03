# Tutorial 03: HITL with Slack Approvals

Wire up Slack so your team can approve or deny agent actions in real time.
When an agent proposes a high-risk action, a message appears in your Slack channel.
A human clicks approve or deny. The agent proceeds — or stops.

---

## What you'll learn

- How to configure a Slack bot for HITL approvals
- How to wire `CallbackApprovalChannel` to Slack
- How to handle approvals and denials from Slack interactions
- What the approval record looks like in the audit log

---

## Prerequisites

```bash
pip install "shani[core]" slack-sdk
```

A Slack app with the following scopes:
- `chat:write` — post messages
- `channels:read` — find your approval channel

---

## Step 1: Create a Slack app

1. Go to `https://api.slack.com/apps` → **Create New App**
2. Choose **From scratch** → name it `Shani Approvals`
3. Under **OAuth & Permissions**, add scopes: `chat:write`, `channels:read`
4. Install the app to your workspace
5. Copy the **Bot User OAuth Token** (`xoxb-...`)

Set it as an environment variable:

```bash
export SLACK_BOT_TOKEN="xoxb-your-token-here"
export SLACK_APPROVAL_CHANNEL="#shani-approvals"  # your approval channel
```

---

## Step 2: Build the approval channel

```python
import os
import json
from slack_sdk import WebClient
from shani.hitl.channel.channels import CallbackApprovalChannel

slack = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
channel = os.environ["SLACK_APPROVAL_CHANNEL"]

def notify_slack(req: dict):
    """Send an approval request to Slack."""
    slack.chat_postMessage(
        channel=channel,
        text=f"[Shani] Approval required: `{req['decision_type']}` on `{req['target']}`",
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Shani: Approval Required*\n"
                        f"• *Type:* `{req['decision_type']}`\n"
                        f"• *Target:* `{req['target']}`\n"
                        f"• *Authority required:* `{req['required_authority']}`\n"
                        f"• *Request ID:* `{req['request_id']}`\n"
                        f"• *Description:* {req.get('description', 'N/A')}"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "value": json.dumps({
                            "action": "approve",
                            "request_id": req["request_id"],
                        }),
                        "action_id": "shani_approve",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Deny"},
                        "style": "danger",
                        "value": json.dumps({
                            "action": "deny",
                            "request_id": req["request_id"],
                        }),
                        "action_id": "shani_deny",
                    },
                ],
            },
        ],
    )

approval_channel = CallbackApprovalChannel(
    on_new_request=lambda req: notify_slack(req.to_display_dict())
)
```

---

## Step 3: Build the gate

```python
from shani import ShaniEvaluator, StaticAuthorityProvider
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate

agents = {
    "my-agent/v1": AgentIdentity(
        agent_id="my-agent/v1",
        granted_dsal=3,
        allowed_decision_types=frozenset([
            "remediation", "configuration_change", "network_action"
        ]),
    )
}

gate = HITLGate(
    evaluator=ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    ),
    channel=approval_channel,
    approval_required_at_dsal=2,
    timeout_minutes=30,
)
```

---

## Step 4: Handle Slack interactions

When a human clicks Approve or Deny in Slack, Slack sends a POST request to
your app's **Interactivity URL**. Handle it in your webhook:

```python
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route("/slack/interactions", methods=["POST"])
def slack_interactions():
    payload = json.loads(request.form["payload"])

    for action in payload.get("actions", []):
        value = json.loads(action["value"])
        request_id = value["request_id"]
        operator = payload["user"]["name"]  # Slack username

        if value["action"] == "approve":
            approval_channel.approve(
                request_id,
                authority=f"{operator}@your-org.com",
                note="Approved via Slack",
            )
            # Update the Slack message to show approval
            slack.chat_update(
                channel=payload["channel"]["id"],
                ts=payload["message"]["ts"],
                text=f"✅ Approved by {operator}",
            )

        elif value["action"] == "deny":
            approval_channel.deny(
                request_id,
                authority=f"{operator}@your-org.com",
                note="Denied via Slack",
            )
            slack.chat_update(
                channel=payload["channel"]["id"],
                ts=payload["message"]["ts"],
                text=f"❌ Denied by {operator}",
            )

    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(port=3000)
```

Set your Slack app's **Interactivity Request URL** to:
```
https://your-domain.com/slack/interactions
```

For local development, use [ngrok](https://ngrok.com):
```bash
ngrok http 3000
# Use the ngrok URL as your Interactivity Request URL
```

---

## Step 5: What the flow looks like

```
Agent proposes isolate("host:prod-db-12")
       ↓
Shani evaluates → D-SAL 2 → HITL required
       ↓
Slack message posted to #shani-approvals:
  ┌─────────────────────────────────────────┐
  │ Shani: Approval Required                │
  │ • Type:      network_action             │
  │ • Target:    host:prod-db-12            │
  │ • Authority: SecOps-Lead                │
  │ • Request:   abc-123                    │
  │                                         │
  │  [✅ Approve]  [❌ Deny]               │
  └─────────────────────────────────────────┘
       ↓
alice clicks ✅ Approve
       ↓
Shani issues signed ADO:
  authority: "alice@your-org.com"
  dsal: 2
  proposal_hash: sha256:...
  signature: hmac:...
       ↓
Agent executes. Audit log records:
  {
    "step": "isolate",
    "status": "AUTHORIZED",
    "authority": "alice@your-org.com",
    "dsal": 2,
    "issued_at": "2026-05-27T..."
  }
```

**alice's approval is cryptographically bound to the ADO.** The audit log
proves not just that the action happened, but that alice explicitly authorized it.

---

## Timeout handling

If no one approves within `timeout_minutes`, the gate returns a `DeniedDecision`:

```python
# The gate returns DeniedDecision if the request times out
result = gate.evaluate(proposal)

if isinstance(result, DeniedDecision):
    summary = result.to_human_summary()
    print(f"Denied: {summary['reason']}")
    # → "HITL approval timed out after 30 minutes"
```

Post a follow-up message to Slack when this happens:

```python
def on_timeout(request_id: str):
    slack.chat_postMessage(
        channel=channel,
        text=f"⏰ Shani: Request `{request_id}` timed out. Agent action was denied.",
    )
```

---

## Production checklist

- [ ] Slack bot token stored in a secrets manager (not in environment variables)
- [ ] Interactivity URL is HTTPS
- [ ] Slack request signatures verified (`X-Slack-Signature` header)
- [ ] `timeout_minutes` set to match your team's SLA
- [ ] Audit log is written to persistent storage (not just local disk)
- [ ] `FileNonceStore` used instead of `InMemoryNonceStore` (persists across restarts)

**Switching to FileNonceStore:**

```python
from shani.security.replay_store import FileNonceStore

evaluator = ShaniEvaluator(
    authority_provider=StaticAuthorityProvider(max_dsal=3),
    decision_policy=DecisionPolicyProvider(agent_registry=agents),
    nonce_store=FileNonceStore("shani_nonces.jsonl"),  # append-only, survives restarts
)
```

---

## What's next

- **[Policy Reference](../POLICY_REFERENCE.md)** — Customize authority roles to match your Slack usernames
- **[Architecture](../ARCHITECTURE.md)** — Understand how the HITLGate fits into the full pipeline
- **[Tutorial 02](02_langgraph_integration.md)** — Combine Slack approvals with LangGraph integration
