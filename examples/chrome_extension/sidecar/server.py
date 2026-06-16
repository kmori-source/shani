"""
examples/chrome_extension/sidecar/server.py

Shani Chrome Extension Sidecar — a local HTTP server that handles approval
requests from the Chrome extension.

Flow:
    Chrome Extension (background.js)
        ↓ POST /approve
    Sidecar
        ├─ ChromeAdapter.handle_message()
        ├─ gate.evaluate()  ← Shani evaluation engine
        │     ├─ D-SAL calculation
        │     ├─ Risk assessment
        │     └─ HITL (waits for human approval if D-SAL >= 2)
        └─ ADO → Capability → token returned
        ↓ {"token": "...", "allowed_ops": [...]}  or  {"request_id": "...", "status": "pending"}
    Chrome Extension
        ↓ POST /execute (token + operation + target)
    Sidecar
        ├─ ChromeAdapter.execute()
        └─ Returns result
        ↓ popup.js polls GET /pending
    Popup UI
        ↓ POST /decision (approve/deny)
    Sidecar
        └─ channel.approve() / channel.deny()

Endpoints:
    POST /approve       Approval request → token or request_id
    POST /execute       token + operation → execution result
    POST /collect       Poll for pending request_id result
    GET  /pending       List of HITL pending approvals (used by popup.js)
    POST /decision      Approve or deny (used by popup.js)
    GET  /health        Health check

Launch:
    python server.py
    python server.py --port 7891 --hitl-dsal 2
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Shani bootstrap ───────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

    _spec = _iu.spec_from_file_location(
        "_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"),
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="shani")

from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision  # noqa: E402
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity  # noqa: E402
from shani.hitl import HITLGate  # noqa: E402
from shani.hitl.channel.channels import CallbackApprovalChannel  # noqa: E402
from shani.schemas.decision import DecisionType  # noqa: E402
from shani.adapters.chrome import ChromeAdapter  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Sidecar initialization
# ─────────────────────────────────────────────────────────────────────────────


def build_sidecar(hitl_dsal: int = 2) -> ChromeAdapter:
    channel = CallbackApprovalChannel()

    agents = {
        "chrome-extension/v1": AgentIdentity(
            agent_id="chrome-extension/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(
                [
                    DecisionType.BROWSER_ACTION.value,
                    DecisionType.DATA_ACCESS.value,
                ]
            ),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    gate = HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=hitl_dsal,
        timeout_minutes=10,
    )
    return ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Handler
# ─────────────────────────────────────────────────────────────────────────────

adapter: ChromeAdapter | None = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send(self, data: dict, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self._send({"ok": True, "service": "shani-chrome-sidecar"})

        elif self.path == "/pending":
            # popup.js polls to get the list of pending approvals
            channel = adapter._gate._channel
            pending = []
            for req in channel.get_pending():
                d = req.to_display_dict()
                pending.append(
                    {
                        "request_id": req.request_id,
                        "action": d.get("action", ""),
                        "target": req.target,
                        "intent": req.intent,
                        "blast_radius": d.get("blast_radius", ""),
                        "dsal": d.get("dsal_requested", 0),
                        "required_authority": req.required_authority,
                        "timeout_at": req.timeout_at.isoformat(),
                        "evidence": req.evidence_summary,
                        "proposed_by": req.proposed_by,
                    }
                )
            self._send({"pending": pending})

        else:
            self._send({"error": "Not found"}, 404)

    def do_POST(self):
        body = self._read_body()

        if self.path == "/approve":
            # Action approval request from Chrome extension
            result = adapter.handle_message(body)
            if result.get("approved") is None:
                # Waiting for HITL
                self._send(result, 202)
            elif result.get("approved"):
                self._send(result, 200)
            elif "error" in result:
                self._send(result, 400)
            else:
                self._send(result, 403)

        elif self.path == "/collect":
            # Poll for HITL result
            request_id = body.get("request_id")
            if not request_id:
                self._send({"error": "request_id required"}, 400)
                return
            result = adapter.collect(request_id)
            self._send(result)

        elif self.path == "/execute":
            # Execute action with approved token
            token = body.get("token")
            operation = body.get("operation", "http_get")
            target = body.get("target", "")
            payload = body.get("payload")
            if not token:
                self._send({"error": "token required"}, 400)
                return
            result = adapter.execute(token, operation, target, payload)
            status = 200 if result.get("success") else 400
            self._send(result, status)

        elif self.path == "/decision":
            # Approve or deny from popup.js
            request_id = body.get("request_id")
            action = body.get("action")  # "approve" or "deny"
            authority = body.get("authority", "popup-user")
            note = body.get("note", "")

            channel = adapter._gate._channel
            try:
                if action == "approve":
                    channel.approve(request_id, authority, note)
                    self._send({"ok": True, "action": "approved", "by": authority})
                elif action == "deny":
                    channel.deny(request_id, authority, note)
                    self._send({"ok": True, "action": "denied", "by": authority})
                else:
                    self._send({"error": f"Unknown action: {action}"}, 400)
            except KeyError:
                self._send({"error": f"Unknown request_id: {request_id}"}, 404)

        else:
            self._send({"error": "Not found"}, 404)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def run(port: int = 7891, hitl_dsal: int = 2):
    global adapter
    adapter = build_sidecar(hitl_dsal=hitl_dsal)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Shani Chrome Extension Sidecar on http://127.0.0.1:{port}")
    print(f"HITL required at D-SAL >= {hitl_dsal}")
    print()
    print("Endpoints:")
    print(f"  POST /approve   — browser action approval request")
    print(f"  POST /execute   — execute action with token")
    print(f"  POST /collect   — poll HITL result")
    print(f"  GET  /pending   — list of pending approvals (used by popup.js)")
    print(f"  POST /decision  — approve or deny (used by popup.js)")
    print(f"  GET  /health    — health check")
    print()
    server.serve_forever()


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Shani Chrome Extension Sidecar")
    p.add_argument("--port", type=int, default=7891, help="Listen port (default: 7891)")
    p.add_argument(
        "--hitl-dsal", type=int, default=2, help="D-SAL threshold for human approval (default: 2)"
    )
    args = p.parse_args()
    run(port=args.port, hitl_dsal=args.hitl_dsal)
