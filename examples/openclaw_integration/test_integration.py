"""
examples/openclaw_integration/test_integration.py

OpenClaw Skill → Shani Sidecar integration test.

Spins up a real HTTP server and reproduces the same flow that a Skill would use.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location("_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"))
    _mod = _iu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="shani")


# ── Start sidecar in-process ────────────────────────────────────────────────

def start_sidecar(port: int = 18765) -> threading.Thread:
    from shani_sidecar.server import ShaniSidecar, Handler, sidecar as _
    import shani_sidecar.server as srv
    from http.server import ThreadingHTTPServer

    srv.sidecar = ShaniSidecar(hitl_dsal=2)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)  # wait for startup
    return t, srv.sidecar


# ── HTTP client (same calls a real Skill would make) ─────────────────────────

BASE = "http://127.0.0.1:18765"

def post(path: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{BASE}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def get(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=15) as r:
        return json.loads(r.read())


# ── Tests ───────────────────────────────────────────────────────────────────

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
failures = []

def ok(msg): print(f"  {PASS} {msg}")
def fail(msg): failures.append(msg); print(f"  {FAIL} {msg}")
def section(t): print(f"\n  ── {t} ──────────────────────────────────────")


def test_health():
    section("Health check")
    r = get("/health")
    assert r.get("ok"), f"Health check failed: {r}"
    ok("GET /health → ok")


def test_dsal1_auto_approve(sidecar):
    section("D-SAL 1 auto-approval (GET)")

    # Step 1: Skill calls /approve
    r = post("/approve", {
        "decision_type": "data_access",
        "target": "https://api.example.com/status",
        "description": "External API status check — periodic health check",
        "evidence": [{"source": "monitor", "content": "health check triggered", "confidence": 0.9}],
        "confidence": 0.9,
        "blast_radius": "isolated",
    })

    assert r.get("approved") is True, f"Should be auto-approved: {r}"
    assert "token" in r
    assert "http_get" in r.get("allowed_ops", [])
    ok(f"POST /approve → approved, token={r['token'][:8]}...")

    # Step 2: execute with token
    token = r["token"]
    r2 = post("/execute", {
        "token": token,
        "operation": "http_get",
        "target": "https://api.example.com/status",
    })

    assert r2.get("success"), f"Execute failed: {r2}"
    ok(f"POST /execute → success")

    # Step 3: attempt to reuse token (replay prevention)
    r3 = post("/execute", {
        "token": token,
        "operation": "http_get",
        "target": "https://api.example.com/status",
    })
    assert not r3.get("success"), "Should fail: token already used"
    ok(f"Replay blocked: {r3.get('error')}")


def test_dsal2_hitl(sidecar):
    section("D-SAL 2 HITL (POST) — async pattern")

    # Step 1: /approve → returns request_id (pending)
    r = post("/approve", {
        "decision_type": "configuration_change",
        "target": "https://api.example.com/reports",
        "description": "POST summary report to external API — sending LLM-generated summary.",
        "evidence": [{"source": "openclaw-brain", "content": "LLM-generated summary", "confidence": 0.85}],
        "confidence": 0.85,
        "blast_radius": "limited",
    })

    assert r.get("status") == "pending" or r.get("approved") is True, f"Unexpected: {r}"

    if r.get("approved") is True:
        # auto-approved because of low risk
        ok(f"POST /approve → auto-approved (low risk), token={r['token'][:8]}...")
        token = r["token"]
    else:
        # HITL path: receive request_id then approve
        request_id = r["request_id"]
        ok(f"POST /approve → pending, request_id={request_id[:8]}...")

        # Step2: human (e.g. Slack bot) approves via /decision
        dr = post("/decision", {
            "request_id": request_id,
            "action": "approve",
            "authority": "operator@example.com",
            "note": "test approval",
        })
        ok(f"POST /decision → {dr}")

        # Step3: /collect to retrieve token
        for _ in range(10):
            cr = post("/collect", {"request_id": request_id})
            if cr.get("status") != "pending":
                break
            time.sleep(0.1)
        assert cr.get("approved"), f"collect failed: {cr}"
        token = cr["token"]
        ok(f"POST /collect → approved, token={token[:8]}...")

    # Step 4: execute with token
    r2 = post("/execute", {
        "token": token,
        "operation": "http_post",
        "target": "https://api.example.com/reports",
        "payload": {"summary": "test summary"},
    })
    assert r2.get("success"), f"Execute failed: {r2}"
    ok(f"POST /execute → success")


def test_dsal2_hitl_deny(sidecar):
    section("D-SAL 2 HITL deny — async pattern")

    r = post("/approve", {
        "decision_type": "configuration_change",
        "target": "https://api.example.com/danger",
        "description": "Dangerous operation",
        "evidence": [{"source": "test", "content": "dangerous change", "confidence": 0.5}],
        "confidence": 0.5,
    })

    if r.get("approved") is False:
        ok(f"POST /approve → immediately denied: {r.get('reason', '')[:50]}")
        return

    if r.get("status") == "pending":
        request_id = r["request_id"]
        ok(f"POST /approve → pending, request_id={request_id[:8]}...")

        # human denies
        post("/decision", {
            "request_id": request_id,
            "action": "deny",
            "authority": "operator@example.com",
            "note": "deemed dangerous",
        })

        for _ in range(10):
            cr = post("/collect", {"request_id": request_id})
            if cr.get("status") != "pending":
                break
            time.sleep(0.1)
        assert not cr.get("approved"), f"Should be denied: {cr}"
        ok(f"POST /collect → denied: {cr.get('reason', '')[:50]}")


def test_wrong_operation(sidecar):
    section("Blocking disallowed operations")

    # attempt POST with data_access (GET only)
    r = post("/approve", {
        "decision_type": "data_access",
        "target": "https://api.example.com/data",
        "description": "Data read — health check",
        "evidence": [{"source": "monitor", "content": "check request", "confidence": 0.9}],
        "blast_radius": "isolated",
    })
    # data_access + isolated + evidence → D-SAL 1 → auto-approved
    assert r.get("approved") is True, f"Should be auto-approved: {r}"
    token = r.get("token")
    assert token, f"No token: {r}"

    # http_post is not permitted under data_access
    r2 = post("/execute", {
        "token": token,
        "operation": "http_post",  # ← not permitted
        "target": "https://api.example.com/data",
        "payload": {},
    })
    assert not r2.get("success")
    ok(f"Blocked: http_post on data_access → {r2.get('type')}")


if __name__ == "__main__":
    print("=" * 55)
    print("  OpenClaw + Shani Sidecar Integration Test")
    print("=" * 55)

    _, sidecar = start_sidecar(18765)

    test_health()
    test_dsal1_auto_approve(sidecar)
    test_dsal2_hitl(sidecar)
    test_dsal2_hitl_deny(sidecar)
    test_wrong_operation(sidecar)

    print("\n" + "=" * 55)
    if failures:
        print(f"  FAILED: {len(failures)}")
        for f in failures: print(f"    • {f}")
        sys.exit(1)
    else:
        print("  All tests passed")
        print()
        print("  Integration flow verified:")
        print("    OpenClaw Skill → POST /approve → token")
        print("    token → POST /execute → execute")
        print("    D-SAL 1: auto-approve")
        print("    D-SAL 2: HITL (via /decision from Slack bot or Web UI)")
        print("    token reuse: replay blocked")
        print("    disallowed operation: OperationNotAllowed blocked")
    print("=" * 55)
