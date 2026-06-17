# examples/nanoclaw_sidecar/start_sidecar.py
#
# Shani sidecar server for nanoclaw integration.
# Listens on 0.0.0.0:8765 so nanoclaw containers can reach it via 172.17.0.1:8765.
#
# Usage:
#   python examples/nanoclaw_sidecar/start_sidecar.py
#
# Environment variables:
#   SHANI_HITL_AUTO=approve      — auto-approve all HITL requests (for testing)
#   SHANI_HITL_AUTO=deny         — auto-deny all HITL requests (for testing)
#   SHANI_HOST                   — bind address (default: 0.0.0.0)
#   SHANI_PORT                   — port (default: 8765)
#   SLACK_BOT_TOKEN              — Slack Bot OAuth Token (xoxb-...)
#   SLACK_SIGNING_SECRET         — Slack Signing Secret
#   SLACK_APPROVAL_CHANNEL       — Slack channel for HITL notifications (e.g. #shani-approvals)
#   SLACK_INTERACTIONS_PORT      — port for Slack interactions webhook (default: 3000)

import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shani import ShaniEvaluator, StaticAuthorityProvider
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer

# ── Environment ──────────────────────────────────────────────────────────────

HITL_AUTO             = os.environ.get("SHANI_HITL_AUTO", "").lower()
SLACK_BOT_TOKEN       = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_SIGNING_SECRET  = os.environ.get("SLACK_SIGNING_SECRET", "")
SLACK_CHANNEL         = os.environ.get("SLACK_APPROVAL_CHANNEL", "#shani-approvals")
SLACK_PORT            = int(os.environ.get("SLACK_INTERACTIONS_PORT", "3000"))

USE_SLACK = bool(SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET)

# ── Slack client (optional) ───────────────────────────────────────────────────

if USE_SLACK:
    from slack_sdk import WebClient
    slack_client = WebClient(token=SLACK_BOT_TOKEN)
    print(f"[Slack] Slack integration enabled → {SLACK_CHANNEL}")
else:
    slack_client = None
    print("[Slack] Slack integration disabled (SLACK_BOT_TOKEN not set)")

# ── Agent registry ────────────────────────────────────────────────────────────

agents = {
    "nanoclaw-agent/v1": AgentIdentity(
        agent_id="nanoclaw-agent/v1",
        granted_dsal=3,
        allowed_decision_types=frozenset([
            "remediation", "configuration_change", "data_access",
            "network_action",
        ]),
    )
}

# ── Slack notification ────────────────────────────────────────────────────────

def notify_slack(req) -> None:
    """Post an approval request card to Slack."""
    if not USE_SLACK or slack_client is None:
        return
    d = req.to_display_dict()
    short_id = d["request_id"]
    try:
        slack_client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=f"[Shani] Approval required: `{d['action']}`",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Shani: Approval Required*\n"
                            f"• *Action:* `{d['action']}`\n"
                            f"• *Authority needed:* `{d['authority_needed']}`\n"
                            f"• *Blast radius:* `{d['blast_radius']}`\n"
                            f"• *Evidence:* {', '.join(d.get('evidence', []))}\n"
                            f"• *Request ID:* `{short_id}`\n"
                            f"• *Timeout:* {d['timeout']}"
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
                            "value": json.dumps({"action": "approve", "request_id": short_id}),
                            "action_id": "shani_approve",
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "❌ Deny"},
                            "style": "danger",
                            "value": json.dumps({"action": "deny", "request_id": short_id}),
                            "action_id": "shani_deny",
                        },
                    ],
                },
            ],
        )
        print(f"[Slack] Notification sent for request {short_id}")
    except Exception as e:
        print(f"[Slack] Failed to send notification: {e}")

# ── HITL channel ──────────────────────────────────────────────────────────────

def on_new_request(req) -> None:
    print(f"[HITL] {req.to_display_dict()}")
    notify_slack(req)

channel = CallbackApprovalChannel(on_new_request=on_new_request)

# ── Gate ──────────────────────────────────────────────────────────────────────

gate = HITLGate(
    evaluator=ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    ),
    channel=channel,
    approval_required_at_dsal=2,
    timeout_minutes=10,
)

# ── Auto-respond (for testing) ────────────────────────────────────────────────

def auto_respond() -> None:
    """Auto-approve or auto-deny HITL requests for testing."""
    seen: set = set()
    while True:
        time.sleep(0.5)
        try:
            for req in channel.get_pending():
                if req.request_id in seen:
                    continue
                seen.add(req.request_id)
                time.sleep(0.5)
                if HITL_AUTO == "deny":
                    channel.deny(req.request_id, "operator@example.com", "auto-deny")
                    print(f"[HITL] ✗ Auto-denied: {req.request_id}")
                else:
                    channel.approve(req.request_id, "operator@example.com", "auto-approve")
                    print(f"[HITL] ✓ Auto-approved: {req.request_id}")
        except Exception as e:
            print(f"[HITL] auto_respond error: {e}")

if HITL_AUTO in ("approve", "deny"):
    print(f"[HITL] Auto-mode: {HITL_AUTO}")
    threading.Thread(target=auto_respond, daemon=True).start()
else:
    print("[HITL] Manual mode — approve via Slack button or POST /v1/approve")

# ── Slack interactions webhook ────────────────────────────────────────────────

def verify_slack_signature(body: bytes, timestamp: str, signature: str) -> bool:
    """Verify Slack request signature (HMAC-SHA256)."""
    base = f"v0:{timestamp}:{body.decode()}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        base.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def resolve_short_id(short_id: str) -> str:
    """Resolve 8-char short ID to full UUID."""
    if len(short_id) > 8:
        return short_id
    matches = [
        r.request_id for r in channel.get_all()
        if r.request_id.startswith(short_id)
    ]
    if len(matches) == 1:
        return matches[0]
    raise KeyError(f"Cannot resolve short ID: {short_id} (matches: {matches})")


class SlackInteractionsHandler(BaseHTTPRequestHandler):
    """Handles Slack button clicks (approve/deny)."""

    def log_message(self, fmt, *args):
        print(f"[Slack webhook] {fmt % args}")

    def do_POST(self):  # noqa: N802
        if self.path != "/slack/interactions":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        # Verify Slack signature
        if SLACK_SIGNING_SECRET:
            timestamp = self.headers.get("X-Slack-Request-Timestamp", "")
            signature = self.headers.get("X-Slack-Signature", "")
            if not verify_slack_signature(body, timestamp, signature):
                self.send_response(401)
                self.end_headers()
                print("[Slack webhook] Signature verification failed")
                return

        # Parse Slack payload
        from urllib.parse import parse_qs
        parsed = parse_qs(body.decode())
        payload = json.loads(parsed.get("payload", ["{}"])[0])

        operator = payload.get("user", {}).get("name", "unknown")
        channel_id = payload.get("channel", {}).get("id", "")
        message_ts = payload.get("message", {}).get("ts", "")

        for action in payload.get("actions", []):
            value = json.loads(action.get("value", "{}"))
            short_id = value.get("request_id", "")
            act = value.get("action", "")

            try:
                full_id = resolve_short_id(short_id)
                authority = f"{operator}@slack"

                if act == "approve":
                    channel.approve(full_id, authority=authority, note="Approved via Slack")
                    result_text = f"✅ Approved by {operator}"
                    print(f"[Slack] Approved: {short_id} by {operator}")
                elif act == "deny":
                    channel.deny(full_id, authority=authority, note="Denied via Slack")
                    result_text = f"❌ Denied by {operator}"
                    print(f"[Slack] Denied: {short_id} by {operator}")
                else:
                    result_text = f"Unknown action: {act}"

                # Update Slack message to show result
                if slack_client and channel_id and message_ts:
                    slack_client.chat_update(
                        channel=channel_id,
                        ts=message_ts,
                        text=result_text,
                        blocks=[],
                    )

            except Exception as e:
                print(f"[Slack webhook] Error processing action: {e}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')


def start_slack_webhook() -> None:
    """Start Slack interactions webhook server in background thread."""
    srv = ThreadingHTTPServer(("0.0.0.0", SLACK_PORT), SlackInteractionsHandler)
    print(f"[Slack webhook] Listening on 0.0.0.0:{SLACK_PORT}/slack/interactions")
    srv.serve_forever()


if USE_SLACK:
    threading.Thread(target=start_slack_webhook, daemon=True).start()

# ── Shani sidecar ─────────────────────────────────────────────────────────────

server = ShaniSidecarServer(gate=gate, channel=channel, host="0.0.0.0", port=8765)
print("Shani sidecar listening on 0.0.0.0:8765")
server.serve_forever()
