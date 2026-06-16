"""
examples/openclaw_integration/shani_sidecar/server.py

Shani Sidecar — HTTP approval endpoint called by OpenClaw Skills.

Flow:
    OpenClaw Skill
        ↓ POST /approve
    Shani Sidecar
        ├─ build DecisionProposal
        ├─ gate.evaluate()  ← Shani evaluation engine
        │     ├─ D-SAL check
        │     ├─ evidence check
        │     └─ HITL (waits for approval if D-SAL ≥ 2)
        └─ ADO → Capability → return token
        ↓ { "token": "...", "allowed_ops": [...] }
    OpenClaw Skill
        ↓ POST /execute  (token + operation + target)
    Shani Sidecar
        ├─ validate token
        ├─ Capability.http_get() / http_post() etc.
        └─ return result

Endpoints:
    POST /approve       Approval request → token
    POST /execute       token + operation → execution result
    GET  /pending       list of pending approvals (for external UI / Slack bot)
    POST /decision      approve or deny (for external UI / Slack bot)
    GET  /health        Health check

Launch:
    python server.py
    python server.py --port 8765 --hitl-dsal 2
"""

from __future__ import annotations

import json
import os
import sys
import time
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from typing import Any

# ── Shani bootstrap ───────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

try:
    import pydantic  # noqa
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl

    _spec = _iu.spec_from_file_location(
        "_compat", str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py")
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="shani")

from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius, DeniedDecision
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem
from shani.boundary.capability import ExecutionBoundary, Capability


# ─────────────────────────────────────────────────────────────────────────────
# Sidecar State
# ─────────────────────────────────────────────────────────────────────────────


class ShaniSidecar:
    def __init__(self, hitl_dsal: int = 2):
        self.channel = CallbackApprovalChannel()
        agents = {
            "openclaw-skill/v1": AgentIdentity(
                agent_id="openclaw-skill/v1",
                granted_dsal=2,
                allowed_decision_types=frozenset(
                    [
                        "data_access",
                        "configuration_change",
                        "remediation",
                        "network_action",
                    ]
                ),
            )
        }
        evaluator = ShaniEvaluator(
            authority_provider=StaticAuthorityProvider(max_dsal=3),
            decision_policy=DecisionPolicyProvider(agent_registry=agents),
        )
        self.gate = HITLGate(
            evaluator=evaluator,
            channel=self.channel,
            approval_required_at_dsal=hitl_dsal,
            timeout_minutes=10,
        )
        self.boundary = ExecutionBoundary(self.gate)

        # token → Capability map (holds approved Capabilities)
        self._caps: dict[str, Capability] = {}
        # request_id → DecisionProposal (holds proposal during HITL)
        self._pending_proposals: dict[str, object] = {}
        self._lock = threading.Lock()

    def request_approval(self, body: dict) -> dict:
        """
        POST /approve handler.

        D-SAL 1 (auto-approve): returns token immediately
        D-SAL 2+ (HITL): returns request_id → Skill polls /collect

        requested_dsal is not accepted.
        Shani computes D-SAL from decision_type + context.
        """
        try:
            dt = DecisionType(body.get("decision_type", "data_access"))
        except ValueError:
            return {"error": f"Unknown decision_type: {body.get('decision_type')}"}

        try:
            br = BlastRadius(body.get("blast_radius", "limited"))
        except ValueError:
            br = BlastRadius.LIMITED

        evidence = []
        for e in body.get("evidence", []):
            evidence.append(
                EvidenceItem(
                    source=e.get("source", "openclaw-skill"),
                    content=e.get("content", ""),
                    confidence=float(e.get("confidence", 0.8)),
                )
            )

        target = body.get("target", "unknown")

        proposal = DecisionProposal(
            decision_type=dt,
            proposed_by="openclaw-skill/v1",
            description=body.get("description", f"{dt.value} on {target}"),
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=evidence,
            confidence=float(body.get("confidence", 0.8)),
            reversibility=bool(body.get("reversibility", True)),
            blast_radius=br,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
        )

        # D-SAL 1 → immediate evaluation via gate.evaluate() (non-blocking)
        # D-SAL 2+ → async registration via gate.submit() → poll /collect
        effective_dsal = self.gate._get_effective_dsal(proposal)

        if effective_dsal < self.gate._threshold:
            # auto-approve path (non-blocking)
            ado = self.gate.evaluate(proposal)
            if isinstance(ado, DeniedDecision):
                return {"approved": False, "reason": ado.reason}
            cap = self.boundary.issue_capability(ado, proposal)
            token = str(uuid.uuid4())
            with self._lock:
                self._caps[token] = cap
            return {
                "approved": True,
                "token": token,
                "allowed_ops": sorted(cap._allowed),
                "target_prefix": cap._target_prefix,
                "expires_at": ado.expires_at.isoformat(),
                "decision_id": ado.decision_id[:8],
            }
        else:
            # HITL path (async): return request_id
            try:
                request_id = self.gate.submit(proposal)
                with self._lock:
                    self._pending_proposals[request_id] = proposal
                return {"approved": None, "request_id": request_id, "status": "pending"}
            except Exception as e:
                return {"approved": False, "reason": str(e)}

    def execute(self, body: dict) -> dict:
        """
        POST /execute handler.
        Executes an operation using a Capability identified by token + operation + target.
        """
        token = body.get("token")
        operation = body.get("operation")
        target = body.get("target", "")
        payload = body.get("payload", {})

        with self._lock:
            cap = self._caps.pop(token, None)  # single-use: pop on first use

        if cap is None:
            return {"error": "Invalid or already-used token"}

        try:
            if operation == "http_get":
                result = cap.http_get(target)
            elif operation == "http_post":
                result = cap.http_post(target, payload)
            elif operation == "read_file":
                result = cap.read_file(target)
            elif operation == "write_file":
                content = body.get("content", "")
                result = cap.write_file(target, content)
            elif operation == "run_command":
                result = cap.run_command(target)
            else:
                return {"error": f"Unknown operation: {operation}"}

            return {"success": True, "result": result}

        except Exception as e:
            return {"success": False, "error": str(e), "type": type(e).__name__}

    def collect(self, body: dict) -> dict:
        """
        POST /collect handler.
        Polls for the result of a pending HITL request_id.
        Called repeatedly by the Skill after receiving a request_id from /approve.

        returns:
          {"status": "pending"} — still waiting
          {"approved": True, "token": ...} — approved
          {"approved": False, "reason": ...} — denied
        """
        request_id = body.get("request_id")
        if not request_id:
            return {"error": "request_id required"}

        with self._lock:
            proposal = self._pending_proposals.get(request_id)

        try:
            result = self.gate.collect(request_id, proposal)
        except RuntimeError:
            return {"status": "pending"}
        except KeyError as e:
            return {"error": str(e)}

        if hasattr(result, "reason"):
            # DeniedDecision
            with self._lock:
                self._pending_proposals.pop(request_id, None)
            return {"approved": False, "reason": result.reason}

        # ADO → Capability → token
        ado = result
        cap = self.boundary.issue_capability(ado, proposal)
        token = str(uuid.uuid4())
        with self._lock:
            self._caps[token] = cap
            self._pending_proposals.pop(request_id, None)

        return {
            "approved": True,
            "token": token,
            "allowed_ops": sorted(cap._allowed),
            "target_prefix": cap._target_prefix,
            "expires_at": ado.expires_at.isoformat(),
            "decision_id": ado.decision_id[:8],
        }

    def get_pending(self) -> list[dict]:
        """GET /pending — list of HITL pending approvals. Called by Slack bot or Web UI."""
        result = []
        for req in self.channel.get_pending():
            result.append(
                {
                    "request_id": req.request_id,
                    "decision_type": req.decision_type,
                    "target": req.target,
                    "intent": req.intent,
                    "required_authority": req.required_authority,
                    "timeout_at": req.timeout_at.isoformat(),
                    "evidence": req.evidence_summary,
                }
            )
        return result

    def make_decision(self, body: dict) -> dict:
        """POST /decision — approve or deny from Slack bot or Web UI."""
        request_id = body.get("request_id")
        action = body.get("action")  # "approve" or "deny"
        authority = body.get("authority", "unknown")
        note = body.get("note", "")

        if action == "approve":
            self.channel.approve(request_id, authority, note)
            return {"ok": True, "action": "approved", "by": authority}
        elif action == "deny":
            self.channel.deny(request_id, authority, note)
            return {"ok": True, "action": "denied", "by": authority}
        else:
            return {"error": f"Unknown action: {action}"}


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Server
# ─────────────────────────────────────────────────────────────────────────────

sidecar: ShaniSidecar | None = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silent (suppress request logs)

    def _send(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        if self.path == "/health":
            self._send({"ok": True, "service": "shani-sidecar"})
        elif self.path == "/pending":
            self._send({"pending": sidecar.get_pending()})
        else:
            self._send({"error": "Not found"}, 404)

    def do_POST(self):
        body = self._read_body()
        if self.path == "/approve":
            result = sidecar.request_approval(body)
            # pending (HITL) → 202, approved → 200, denied → 403
            status = (
                202
                if result.get("status") == "pending"
                else (200 if result.get("approved") else 403)
            )
            self._send(result, status)
        elif self.path == "/collect":
            self._send(sidecar.collect(body))
        elif self.path == "/execute":
            result = sidecar.execute(body)
            self._send(result, 200 if result.get("success") else 400)
        elif self.path == "/decision":
            self._send(sidecar.make_decision(body))
        else:
            self._send({"error": "Not found"}, 404)


def run(port: int = 8765, hitl_dsal: int = 2):
    global sidecar
    sidecar = ShaniSidecar(hitl_dsal=hitl_dsal)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Shani sidecar running on http://127.0.0.1:{port}")
    print(f"HITL required at D-SAL >= {hitl_dsal}")
    print()
    print("Endpoints:")
    print(f"  POST /approve   — request capability token")
    print(f"  POST /execute   — execute with token")
    print(f"  GET  /pending   — list HITL approvals waiting")
    print(f"  POST /decision  — approve or deny (from Slack bot / UI)")
    print(f"  GET  /health    — health check")
    print()
    server.serve_forever()


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--hitl-dsal", type=int, default=2)
    args = p.parse_args()
    run(port=args.port, hitl_dsal=args.hitl_dsal)
