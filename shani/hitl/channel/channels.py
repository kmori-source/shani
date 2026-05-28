"""
Shani HITL Channels — built-in approval channel implementations.

Each channel implements the ApprovalChannel protocol.
Add a new channel by implementing two methods: send() and poll().

Included:
    CLIApprovalChannel      — blocks on stdin. For development/testing.
    WebhookApprovalChannel  — POSTs to URL, polls for response.
    CallbackApprovalChannel — stores requests in memory, provides approve/deny methods.
                              Use this when building your own UI.
    SlackApprovalChannel    — stub showing the pattern for Slack integration.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from ..approval.request import ApprovalRequest, ApprovalStatus


# ---------------------------------------------------------------------------
# 1. CLI Channel — development / testing
# ---------------------------------------------------------------------------


class CLIApprovalChannel:
    """
    Interactive CLI approval.

    Blocks on stdin. Shows a formatted decision summary.
    Use for development, demos, and CLI-driven workflows.

    Usage:
        gate = HITLGate(evaluator=evaluator, channel=CLIApprovalChannel())
    """

    def __init__(self, operator_name: str = "cli-operator") -> None:
        self._operator = operator_name
        self._decided: dict[str, ApprovalRequest] = {}

    def send(self, request: ApprovalRequest) -> None:
        """Print summary and block for human input."""
        d = request.to_display_dict()

        print("\n" + "═" * 60)
        print("  🔐 SHANI — APPROVAL REQUIRED")
        print("═" * 60)
        print(f"  Request ID  : {d['request_id']}")
        print(f"  Agent       : {d['agent']}")
        print(f"  Action      : {d['action']}")
        print(f"  Intent      : {d['intent']}")
        print(f"  Blast Radius: {d['blast_radius'].upper()}  |  Reversible: {d['reversible']}")
        print(f"  D-SAL       : {d['dsal_requested']}  |  Confidence: {d['confidence']}")
        print(f"  Authority   : {d['authority_needed']}")
        if d['parent']:
            print(f"  Parent      : {d['parent']}")
        if d['evidence']:
            print("  Evidence    :")
            for e in d['evidence']:
                print(f"    • {e}")
        if d['assumptions']:
            print("  Assumptions :")
            for a in d['assumptions']:
                print(f"    • {a}")
        print(f"  Timeout     : {d['timeout']}")
        print("═" * 60)

        while True:
            raw = input("  [a]pprove / [d]eny / [?]details  > ").strip().lower()
            if raw in ("a", "approve"):
                note = input("  Note (optional): ").strip()
                request.approve(self._operator, note)
                print(f"  ✓ Approved by {self._operator}\n")
                break
            elif raw in ("d", "deny"):
                note = input("  Reason: ").strip()
                request.deny(self._operator, note)
                print(f"  ✗ Denied by {self._operator}\n")
                break
            elif raw in ("?",):
                print(json.dumps(d, indent=2))

        self._decided[request.request_id] = request

    def poll(self, request_id: str) -> ApprovalRequest | None:
        return self._decided.get(request_id)


# ---------------------------------------------------------------------------
# 2. Callback Channel — use this for custom UI
# ---------------------------------------------------------------------------


class CallbackApprovalChannel:
    """
    In-memory channel that holds requests and exposes approve/deny/revoke.

    Use this when building a custom UI (web, mobile, desktop).
    Your UI reads pending requests from this channel and calls approve/deny.

    Usage:
        channel = CallbackApprovalChannel()
        gate = HITLGate(evaluator=evaluator, channel=channel)

        # In your UI backend:
        pending = channel.get_pending()
        channel.approve(request_id, authority="alice@example.com", note="Reviewed EDR alert")
    """

    def __init__(
        self,
        on_new_request: Callable[[ApprovalRequest], None] | None = None,
    ) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()
        self._on_new = on_new_request  # optional callback for push notification

    def send(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._requests[request.request_id] = request
        if self._on_new:
            self._on_new(request)

    def poll(self, request_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._requests.get(request_id)

    def approve(self, request_id: str, authority: str, note: str = "") -> None:
        with self._lock:
            req = self._requests[request_id]
            req.approve(authority, note)

    def deny(self, request_id: str, authority: str, note: str = "") -> None:
        with self._lock:
            req = self._requests[request_id]
            req.deny(authority, note)

    def revoke(self, request_id: str, authority: str, note: str = "") -> None:
        with self._lock:
            req = self._requests[request_id]
            req.revoke(authority, note)

    def get_pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return [r for r in self._requests.values() if r.status == ApprovalStatus.PENDING]

    def get_all(self) -> list[ApprovalRequest]:
        with self._lock:
            return list(self._requests.values())


# ---------------------------------------------------------------------------
# 3. Webhook Channel — POST to external system
# ---------------------------------------------------------------------------


class WebhookApprovalChannel:
    """
    Sends approval requests as JSON POSTs to a webhook URL.
    Polls a response URL for the decision.

    The response endpoint must return JSON:
        {"status": "approved" | "denied", "decided_by": "...", "note": "..."}

    Usage:
        channel = WebhookApprovalChannel(
            send_url="https://approvals.internal/shani/request",
            poll_url_template="https://approvals.internal/shani/request/{request_id}",
        )
    """

    def __init__(
        self,
        send_url: str,
        poll_url_template: str,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._send_url = send_url
        self._poll_template = poll_url_template
        self._headers = headers or {"Content-Type": "application/json"}
        self._timeout = timeout_seconds
        self._sent: set[str] = set()

    def send(self, request: ApprovalRequest) -> None:
        try:
            import urllib.request
            payload = json.dumps(request.to_display_dict()).encode()
            req = urllib.request.Request(self._send_url, data=payload, headers=self._headers, method="POST")
            urllib.request.urlopen(req, timeout=self._timeout)
            self._sent.add(request.request_id)
        except Exception as e:
            raise RuntimeError(f"Webhook send failed: {e}") from e

    def poll(self, request_id: str) -> ApprovalRequest | None:
        if request_id not in self._sent:
            return None
        try:
            import urllib.request
            url = self._poll_template.format(request_id=request_id)
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            if data.get("status") in ("approved", "denied"):
                # Return a minimal mock for protocol compliance
                # Real impl: deserialize full ApprovalRequest from server
                return data
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# 4. Slack Channel stub — pattern for social/chat integration
# ---------------------------------------------------------------------------


class SlackApprovalChannel:
    """
    Slack channel stub.

    Pattern for integrating with any chat platform.

    To implement:
        1. send() → post a Block Kit message with Approve/Deny buttons
        2. Your Slack app receives the button payload via webhook
        3. Your webhook handler calls channel.record_decision(request_id, ...)
        4. poll() checks the recorded decision

    This is a stub — wire up your Slack app token and webhook handler.
    """

    def __init__(
        self,
        bot_token: str = "",
        channel_id: str = "",
        mention: str = "",
    ) -> None:
        self._token = bot_token
        self._channel = channel_id
        self._mention = mention
        self._decisions: dict[str, dict[str, Any]] = {}

    def send(self, request: ApprovalRequest) -> None:
        d = request.to_display_dict()
        # POST to Slack API: chat.postMessage
        # payload = {"channel": self._channel, "blocks": blocks, "text": f"Approval needed: {d['action']}"}
        # requests.post("https://slack.com/api/chat.postMessage", json=payload, headers={"Authorization": f"Bearer {self._token}"})
        print(f"[Slack stub] Would post to {self._channel}: {d['action']} — {d['authority_needed']}")

    def poll(self, request_id: str) -> ApprovalRequest | None:
        return self._decisions.get(request_id)

    def record_decision(
        self, request_id: str, status: str, decided_by: str, note: str = ""
    ) -> None:
        """Called by your Slack webhook handler when a button is clicked."""
        self._decisions[request_id] = {
            "status": status,
            "decided_by": decided_by,
            "note": note,
            "decided_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    def _build_blocks(self, d: dict, request_id: str) -> list[dict]:
        """Build Slack Block Kit message."""
        text = (
            f"*🔐 Shani Approval Required*\n"
            f"*Agent:* {d['agent']}\n"
            f"*Action:* {d['action']}\n"
            f"*Blast Radius:* {d['blast_radius']} | *D-SAL:* {d['dsal_requested']}\n"
            f"*Evidence:* {', '.join(d['evidence']) or 'none'}\n"
            f"*Timeout:* {d['timeout']}"
        )
        if self._mention:
            text = f"{self._mention}\n{text}"
        return [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "✓ Approve"},
                 "style": "primary", "value": f"approve:{request_id}"},
                {"type": "button", "text": {"type": "plain_text", "text": "✗ Deny"},
                 "style": "danger", "value": f"deny:{request_id}"},
            ]},
        ]
