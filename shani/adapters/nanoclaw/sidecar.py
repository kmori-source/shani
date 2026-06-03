"""
shani/adapters/nanoclaw/sidecar.py

ShaniSidecarServer / ShaniSidecarClient

サイドカーパターン（Pattern 1: Pod内サイドカー）:
  nanoclaw コンテナ ─localhost HTTP─> Shani コンテナ（同一 Pod）

サーバーは SHANI_HOST（デフォルト 0.0.0.0）/ SHANI_PORT（デフォルト 8765）で
バインドアドレスを制御する。Pod 内では localhost で到達できる。

エンドポイント:
  POST /v1/evaluate          DecisionProposal → ADO or DeniedDecision
  POST /v1/verify_binding    ADO バインディング検証
  POST /v1/register_executed 実行完了通知
  GET  /healthz              ヘルスチェック

依存追加なし（stdlib の http.server + urllib のみ）。
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
    nanoclaw サイドカー用 HTTP サーバー。

    Shani ガバナンスエンジンを HTTP サービスとして公開する。
    Pod内サイドカーとして動作するため、デフォルトで 0.0.0.0 にバインドする。

    Usage (サイドカーコンテナ内で実行):
        from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer
        server = ShaniSidecarServer(gate=hitl_gate)
        server.serve_forever()   # blocks

    環境変数:
        SHANI_HOST  バインドアドレス（デフォルト: 0.0.0.0）
        SHANI_PORT  ポート番号（デフォルト: 8765）
    """

    def __init__(
        self,
        gate: Any,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self._gate = gate
        self._host = host if host is not None else os.environ.get("SHANI_HOST", _DEFAULT_HOST)
        self._port = port if port is not None else int(os.environ.get("SHANI_PORT", str(_DEFAULT_PORT)))
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    def serve_forever(self) -> None:
        """HTTP サーバーを起動してブロックする。"""
        gate = self._gate

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
                    self._send_json({
                        "type": "denied",
                        "decision_id": result.decision_id,
                        "reason": result.reason,
                    })
                else:
                    self._send_json({
                        "type": "ado",
                        "data": result.model_dump(mode="json"),
                    })

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

        self._server = ThreadingHTTPServer((self._host, self._port), _Handler)
        logger.info("ShaniSidecarServer listening on %s:%d", self._host, self._port)
        self._server.serve_forever()

    def start(self) -> None:
        """バックグラウンドスレッドでサーバーを起動する（テスト・非同期用）。"""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """サーバーを停止する。"""
        if self._server:
            self._server.shutdown()
            self._server = None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ShaniSidecarClient:
    """
    nanoclaw 側で使う HTTP クライアント。GovernanceGate インターフェースを実装する。

    patch_nanoclaw_agent(gate=client) に渡すことで、
    全ツール呼び出しが HTTP 経由でサイドカーに転送される。

    Usage (nanoclaw コンテナ内で実行):
        from shani.adapters.nanoclaw.sidecar import ShaniSidecarClient
        from shani.adapters.nanoclaw import patch_nanoclaw_agent

        client = ShaniSidecarClient()   # SHANI_HOST / SHANI_PORT を参照
        patch_nanoclaw_agent(agent=agent, gate=client, proposed_by="agent/v1")

    環境変数:
        SHANI_HOST  サイドカーのホスト（Pod内では localhost、デフォルト: localhost）
        SHANI_PORT  サイドカーのポート（デフォルト: 8765）
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
        """DecisionProposal をサーバーに送り、ADO または DeniedDecision を返す。"""
        resp = self._post("/v1/evaluate", proposal.model_dump(mode="json"))
        if resp["type"] == "denied":
            return DeniedDecision(
                decision_id=resp["decision_id"],
                reason=resp["reason"],
            )
        return AuthorizedDecisionObject.model_validate(resp["data"])

    def verify_binding(self, ado: AuthorizedDecisionObject, proposal=None) -> bool:
        """ADO のバインディング検証をサーバーに委譲する（署名キーはサーバー側にある）。"""
        payload: dict = {"ado": ado.model_dump(mode="json")}
        if proposal is not None:
            payload["proposal"] = proposal.model_dump(mode="json")
        resp = self._post("/v1/verify_binding", payload)
        return bool(resp.get("ok", False))

    def register_executed(self, ado_or_id, agent_id: str = "") -> None:
        """実行完了をサーバーに通知し、nonce を消費させる。

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
        self._post("/v1/register_executed", {
            "ado": ado_or_id.model_dump(mode="json"),
            "agent_id": agent_id,
        })

    def healthz(self) -> bool:
        """サーバーの起動確認。"""
        url = f"{self._base_url}/healthz"
        req = _urllib_request.Request(url, method="GET")
        try:
            with _urllib_request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read()).get("status") == "ok"
        except URLError:
            return False
