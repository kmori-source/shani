"""
shani/adapters/nanoclaw/sidecar.py

ShaniSidecarServer / ShaniSidecarClient

Sidecar pattern (Pattern 1: In-Pod sidecar):
  nanoclaw container ─localhost HTTP─> Shani container (same Pod)

The server controls its bind address via SHANI_HOST (default 0.0.0.0) /
SHANI_PORT (default 8765). Reachable via localhost within the Pod.

Endpoints:
  POST /v1/evaluate          DecisionProposal → ADO or DeniedDecision
  POST /v1/verify_binding    ADO binding verification
  POST /v1/register_executed execution completion notification
  GET  /healthz              health check

No additional dependencies (stdlib http.server + urllib only).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import request as _urllib_request
from urllib.error import URLError

from ...core.evaluator import DeniedDecision
from ...schemas.decision import AuthorizedDecisionObject, DecisionProposal

logger = logging.getLogger("shani.sidecar")

_DEFAULT_HOST = "0.0.0.0"
_DEFAULT_PORT = 8765


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class ShaniSidecarServer:
    """
    HTTP server for the nanoclaw sidecar.

    Exposes the Shani governance engine as an HTTP service.
    Binds to 0.0.0.0 by default since it operates as an in-Pod sidecar.

    Usage (run inside sidecar container):
        from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer
        server = ShaniSidecarServer(gate=hitl_gate)
        server.serve_forever()   # blocks

    Environment variables:
        SHANI_HOST  bind address (default: 0.0.0.0)
        SHANI_PORT  port number (default: 8765)
    """

    def __init__(
        self,
        gate: Any,
        channel: Any = None,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self._gate = gate
        self._channel = channel
        self._host = host if host is not None else os.environ.get("SHANI_HOST", _DEFAULT_HOST)
        self._port = (
            port if port is not None else int(os.environ.get("SHANI_PORT", str(_DEFAULT_PORT)))
        )
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    def serve_forever(self) -> None:
        """Start the HTTP server and block."""
        gate = self._gate
        channel = self._channel

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: N802
                logger.debug("HTTP %s", fmt % args)

            def _read_json(self) -> dict:
                length = int(self.headers.get("Content-Length", 0))
                return json.loads(self.rfile.read(length))

            def _send_json(self, data: dict, status: int = 200) -> None:
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                if self.path == "/healthz":
                    self._send_json({"status": "ok"})
                else:
                    self._send_json({"error": "not found"}, 404)

            def do_POST(self):  # noqa: N802
                try:
                    if self.path == "/v1/evaluate":
                        self._handle_evaluate()
                    elif self.path == "/v1/verify_binding":
                        self._handle_verify_binding()
                    elif self.path == "/v1/register_executed":
                        self._handle_register_executed()
                    elif self.path == "/v1/approve":
                        self._handle_approve()
                    elif self.path == "/v1/deny":
                        self._handle_deny()
                    else:
                        self._send_json({"error": "not found"}, 404)
                except Exception as exc:
                    logger.error("Sidecar handler error: %s", exc, exc_info=True)
                    self._send_json({"error": str(exc)}, 500)

            def _handle_evaluate(self):
                data = self._read_json()
                proposal = DecisionProposal.model_validate(data)
                result = gate.evaluate(proposal)
                if isinstance(result, DeniedDecision):
                    self._send_json(
                        {
                            "type": "denied",
                            "decision_id": result.decision_id,
                            "reason": result.reason,
                        }
                    )
                else:
                    self._send_json(
                        {
                            "type": "ado",
                            "data": result.model_dump(mode="json"),
                        }
                    )

            def _handle_verify_binding(self):
                data = self._read_json()
                ado = AuthorizedDecisionObject.model_validate(data["ado"])
                proposal = None
                if data.get("proposal"):
                    proposal = DecisionProposal.model_validate(data["proposal"])
                ok = gate.verify_binding(ado, proposal)
                self._send_json({"ok": ok})

            def _handle_register_executed(self):
                data = self._read_json()
                agent_id = data.get("agent_id", "")
                if "ado" in data:
                    ado = AuthorizedDecisionObject.model_validate(data["ado"])
                    gate.register_executed(ado, agent_id=agent_id)
                else:
                    # Require full ADO — decision_id-only path removed (SPEC §5.4 non-conformant).
                    raise ValueError(
                        "register_executed requires 'ado' (full AuthorizedDecisionObject). "
                        "decision_id-only path has been removed to enforce nonce consumption "
                        "and replay prevention (SPEC §5.4)."
                    )
                self._send_json({"ok": True})

            def _handle_approve(self):
                # Approve a pending HITL request.
                # Accepts both full UUID and 8-char short ID.
                data = self._read_json()
                request_id = data["request_id"]
                authority = data.get("authority", "operator")
                note = data.get("note", "")
                if channel is None:
                    raise ValueError("No channel configured on this sidecar.")
                if len(request_id) <= 8:
                    matches = [
                        r.request_id for r in channel.get_all()
                        if r.request_id.startswith(request_id)
                    ]
                    if len(matches) == 1:
                        request_id = matches[0]
                    elif len(matches) == 0:
                        raise KeyError(f"No request found for short ID: {request_id}")
                    else:
                        raise KeyError(f"Ambiguous short ID: {request_id} matches {matches}")
                channel.approve(request_id, authority, note)
                self._send_json({"ok": True, "request_id": request_id})

            def _handle_deny(self):
                # Deny a pending HITL request.
                # Accepts both full UUID and 8-char short ID.
                data = self._read_json()
                request_id = data["request_id"]
                authority = data.get("authority", "operator")
                note = data.get("note", "")
                if channel is None:
                    raise ValueError("No channel configured on this sidecar.")
                if len(request_id) <= 8:
                    matches = [
                        r.request_id for r in channel.get_all()
                        if r.request_id.startswith(request_id)
                    ]
                    if len(matches) == 1:
                        request_id = matches[0]
                    elif len(matches) == 0:
                        raise KeyError(f"No request found for short ID: {request_id}")
                    else:
                        raise KeyError(f"Ambiguous short ID: {request_id} matches {matches}")
                channel.deny(request_id, authority, note)
                self._send_json({"ok": True, "request_id": request_id})

        self._server = ThreadingHTTPServer((self._host, self._port), _Handler)
        logger.info("ShaniSidecarServer listening on %s:%d", self._host, self._port)
        self._server.serve_forever()

    def start(self) -> None:
        """Start the server in a background thread (for testing / async use)."""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ShaniSidecarClient:
    """
    HTTP client for use on the nanoclaw side. Implements the GovernanceGate interface.

    Pass to patch_nanoclaw_agent(gate=client) so that all tool calls are
    forwarded to the sidecar over HTTP.

    Usage (run inside nanoclaw container):
        from shani.adapters.nanoclaw.sidecar import ShaniSidecarClient
        from shani.adapters.nanoclaw import patch_nanoclaw_agent

        client = ShaniSidecarClient()   # reads SHANI_HOST / SHANI_PORT 
        patch_nanoclaw_agent(agent=agent, gate=client, proposed_by="agent/v1")

    Environment variables:
        SHANI_HOST  sidecar host (localhost within the Pod, default: localhost)
        SHANI_PORT  sidecar port (default: 8765)
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 65.0,
    ) -> None:
        host = os.environ.get("SHANI_HOST", "localhost")
        port = int(os.environ.get("SHANI_PORT", str(_DEFAULT_PORT)))
        self._base_url = (base_url or f"http://{host}:{port}").rstrip("/")
        self._timeout = timeout

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self._base_url}{path}"
        body = json.dumps(data).encode()
        req = _urllib_request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _urllib_request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read())
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"Sidecar unreachable [{path}]: {exc}") from exc

    def evaluate(self, proposal: DecisionProposal):
        """Send a DecisionProposal to the server and return an ADO or DeniedDecision."""
        resp = self._post("/v1/evaluate", proposal.model_dump(mode="json"))
        if resp["type"] == "denied":
            return DeniedDecision(
                decision_id=resp["decision_id"],
                reason=resp["reason"],
            )
        return AuthorizedDecisionObject.model_validate(resp["data"])

    def verify_binding(self, ado: AuthorizedDecisionObject, proposal=None) -> bool:
        """Delegates ADO binding verification to the server (signing key is on the server side)."""
        payload: dict = {"ado": ado.model_dump(mode="json")}
        if proposal is not None:
            payload["proposal"] = proposal.model_dump(mode="json")
        resp = self._post("/v1/verify_binding", payload)
        return bool(resp.get("ok", False))

    def register_executed(self, ado_or_id, agent_id: str = "") -> None:
        """Notifies the server of execution completion and consumes the nonce.

        ado_or_id must be a full AuthorizedDecisionObject — passing a string
        decision_id is non-conformant with SPEC §5.4 (bypasses nonce consumption
        and replay prevention) and raises TypeError, matching ShaniEvaluator.
        """
        if isinstance(ado_or_id, str):
            raise TypeError(
                "register_executed() requires a full AuthorizedDecisionObject, not a string. "
                "Passing a decision_id string is non-conformant with SPEC §5.4 — it bypasses "
                "nonce consumption and replay prevention. Pass the full ADO object instead."
            )
        self._post(
            "/v1/register_executed",
            {
                "ado": ado_or_id.model_dump(mode="json"),
                "agent_id": agent_id,
            },
        )

    def healthz(self) -> bool:
        """Check that the server is up."""
        url = f"{self._base_url}/healthz"
        req = _urllib_request.Request(url, method="GET")
        try:
            with _urllib_request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read()).get("status") == "ok"
        except URLError:
            return False
