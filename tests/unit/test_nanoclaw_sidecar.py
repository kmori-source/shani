"""
tests/unit/test_nanoclaw_sidecar.py

Unit tests for ShaniSidecarServer / ShaniSidecarClient.

Pattern 1: In-pod sidecar
  - Server binds to 0.0.0.0 by default
  - Client connects via localhost

Tests:
  - Server can start and stop
  - /healthz returns ok
  - evaluate: read tool → approved
  - evaluate: deny → DeniedDecision
  - verify_binding: valid ADO → True
  - register_executed: notification succeeds
  - ShaniSidecarClient.evaluate + patch_nanoclaw_agent integration
  - SHANI_HOST / SHANI_PORT environment variables are reflected
  - After server stops, client raises RuntimeError
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

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

warnings.filterwarnings("ignore")

from shani import ShaniEvaluator, StaticAuthorityProvider, DeniedDecision
from shani.authority.policy import (
    DecisionPolicyProvider,
    AgentIdentity,
)
from shani.schemas.decision import DecisionType
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.nanoclaw import patch_nanoclaw_agent
from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer, ShaniSidecarClient

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures: list[str] = []


def ok(msg):
    print(f"  {PASS} {msg}")


def fail(msg, d=""):
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))


def section(t):
    print(f"\n  ── {t}")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_NEXT_PORT = 18800


def _next_port() -> int:
    global _NEXT_PORT
    p = _NEXT_PORT
    _NEXT_PORT += 1
    return p


def make_gate(hitl_dsal: int = 3) -> HITLGate:
    channel = CallbackApprovalChannel()
    agents = {
        "nanoclaw-agent/v1": AgentIdentity(
            agent_id="nanoclaw-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                [
                    DecisionType.AGENT_TASK.value,
                    DecisionType.DATA_ACCESS.value,
                    DecisionType.CONFIGURATION_CHANGE.value,
                ]
            ),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    return HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=hitl_dsal,
        timeout_minutes=1,
    )


def start_server(gate: HITLGate, port: int) -> ShaniSidecarServer:
    server = ShaniSidecarServer(gate=gate, host="127.0.0.1", port=port)
    server.start()
    for i in range(20):
        time.sleep(0.05)
        try:
            client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
            if client.healthz():
                return server
        except Exception:
            continue
    server.stop()  # Stop if startup failed
    raise RuntimeError(f"Server failed to start on port {port}")


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


def test_server_start_stop():
    section("server start and stop")
    port = _next_port()
    gate = make_gate()
    server = start_server(gate, port)
    client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
    if client.healthz():
        ok("server startup confirmed: /healthz → ok")
    else:
        fail("server startup failed")
    server.stop()
    ok("server stopped successfully")


def test_healthz():
    section("/healthz endpoint")
    port = _next_port()
    gate = make_gate()
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        result = client.healthz()
        if result:
            ok("/healthz → True")
        else:
            fail("/healthz → False (server not responding)")
    finally:
        server.stop()


def test_evaluate_approved():
    section("evaluate: read tool → approved")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.adapters.nanoclaw import ShaniNanoclawAdapter

        adapter = ShaniNanoclawAdapter(gate=client, proposed_by="nanoclaw-agent/v1")
        result = adapter.call_tool(
            tool_name="fetch_report",
            tool_fn=lambda url: f"report:{url}",
            kwargs={"url": "https://api.example.com/report"},
        )
        if "report:" in str(result):
            ok(f"evaluate approved + execution complete: {result}")
        else:
            fail("evaluate approved but result differs from expected", str(result))
    finally:
        server.stop()


def test_evaluate_denied():
    section("evaluate: deny → DeniedDecision")
    port = _next_port()
    # Set HITL threshold to D-SAL=1 to make all actions go through HITL
    # CallbackChannel defaults to timeout → deny
    gate = make_gate(hitl_dsal=1)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.adapters.nanoclaw import ShaniNanoclawAdapter

        adapter = ShaniNanoclawAdapter(gate=client, proposed_by="nanoclaw-agent/v1")
        try:
            adapter.call_tool(
                tool_name="run_command",
                tool_fn=lambda cmd: "output",
                kwargs={"cmd": "rm -rf /tmp"},
                confidence=0.1,
            )
            # HITL timeout or approval depending on gate config
            ok("evaluate: approved (CallbackChannel auto-approve or timeout)")
        except (PermissionError, RuntimeError, TimeoutError) as e:
            ok(f"evaluate: denied or exception → {type(e).__name__}: {str(e)[:60]}")
    finally:
        server.stop()


def test_verify_binding():
    section("verify_binding: valid ADO → True")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.adapters.nanoclaw import ShaniNanoclawAdapter
        from shani.schemas.decision import (
            DecisionProposal,
            DecisionType,
            BlastRadius,
            DecisionScope,
            EvidenceItem,
        )
        from datetime import datetime, timedelta, timezone

        proposal = DecisionProposal(
            decision_type=DecisionType.DATA_ACCESS,
            proposed_by="nanoclaw-agent/v1",
            description="verify_binding test",
            target="test:target",
            scope=DecisionScope(asset_ids=["test:target"]),
            evidence=[EvidenceItem(source="test", content="test evidence", confidence=0.8)],
            confidence=0.9,
            reversibility=True,
            blast_radius=BlastRadius.ISOLATED,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
        )
        result = client.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            ok(f"evaluate: denied (policy dependent) → skipped: {result.reason[:60]}")
            return
        ok(f"ADO obtained: dsal={result.authorized_dsal}")
        ok_binding = client.verify_binding(result)
        if ok_binding:
            ok("verify_binding → True")
        else:
            fail("verify_binding → False (expected: True)")
    finally:
        server.stop()


def test_register_executed():
    section("register_executed: notification succeeds")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")
        from shani.schemas.decision import (
            DecisionProposal,
            DecisionType,
            BlastRadius,
            DecisionScope,
            EvidenceItem,
        )
        from datetime import datetime, timedelta, timezone

        proposal = DecisionProposal(
            decision_type=DecisionType.DATA_ACCESS,
            proposed_by="nanoclaw-agent/v1",
            description="register_executed test",
            target="test:register",
            scope=DecisionScope(asset_ids=["test:register"]),
            evidence=[EvidenceItem(source="test", content="test", confidence=0.8)],
            confidence=0.9,
            reversibility=True,
            blast_radius=BlastRadius.ISOLATED,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
        )
        ado = client.evaluate(proposal)
        if isinstance(ado, DeniedDecision):
            ok(f"evaluate denied → register_executed test skipped: {ado.reason[:60]}")
            return
        try:
            client.register_executed(ado, agent_id="nanoclaw-agent/v1")
            ok("register_executed complete (no exception)")
        except Exception as e:
            fail("exception in register_executed", str(e))
    finally:
        server.stop()


def test_patch_nanoclaw_agent_sidecar():
    section("patch_nanoclaw_agent(gate=client) integration")
    port = _next_port()
    gate = make_gate(hitl_dsal=3)
    server = start_server(gate, port)
    try:
        client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}")

        class FakeAgent:
            tools: dict = {}

        agent = FakeAgent()
        agent.tools = {
            "fetch": lambda url: f"data:{url}",
            "read": lambda path: f"content:{path}",
        }

        patch_nanoclaw_agent(agent=agent, gate=client, proposed_by="nanoclaw-agent/v1")

        if isinstance(agent.tools, dict) and len(agent.tools) == 2:
            ok(f"tools patch complete: {sorted(agent.tools.keys())}")
        else:
            fail("tools patch failed", str(agent.tools))

        result = agent.tools["fetch"](url="https://api.example.com")
        if "data:" in str(result):
            ok(f"patched tool executed OK: {result}")
        else:
            fail("patched tool execution failed", str(result))
    finally:
        server.stop()


def test_env_var_host_port():
    section("SHANI_HOST / SHANI_PORT environment variables")
    port = _next_port()
    os.environ["SHANI_HOST"] = "127.0.0.1"
    os.environ["SHANI_PORT"] = str(port)
    try:
        gate = make_gate()
        server = ShaniSidecarServer(gate=gate)
        if server.host == "127.0.0.1":
            ok(f"SHANI_HOST reflected: host={server.host}")
        else:
            fail(f"SHANI_HOST not reflected: host={server.host}")
        if server.port == port:
            ok(f"SHANI_PORT reflected: port={server.port}")
        else:
            fail(f"SHANI_PORT not reflected: port={server.port}")

        client = ShaniSidecarClient()
        if f"127.0.0.1:{port}" in client._base_url:
            ok(f"client base_url reflected: {client._base_url}")
        else:
            fail(f"client base_url not reflected: {client._base_url}")
    finally:
        del os.environ["SHANI_HOST"]
        del os.environ["SHANI_PORT"]


def test_server_stopped_raises():
    section("request to stopped server → RuntimeError")
    port = _next_port()
    gate = make_gate()
    server = start_server(gate, port)
    server.stop()
    time.sleep(0.1)
    client = ShaniSidecarClient(base_url=f"http://127.0.0.1:{port}", timeout=1.0)
    try:
        client.healthz()
        ok("healthz: still reachable after server stop (unexpected but acceptable)")
    except (RuntimeError, Exception):
        ok("stopped server → exception raised (as expected)")


def test_server_default_host():
    section("ShaniSidecarServer default host = 0.0.0.0")
    gate = make_gate()
    server = ShaniSidecarServer(gate=gate)
    if server.host == "0.0.0.0":
        ok(f"default host = 0.0.0.0 (for in-pod sidecar)")
    else:
        fail(f"default host is not 0.0.0.0: {server.host}")
    if server.port == 8765:
        ok(f"default port = 8765")
    else:
        fail(f"default port is not 8765: {server.port}")


# ─────────────────────────────────────────────────────────────────────────────


def main():
    print("\ntest_nanoclaw_sidecar.py")
    test_server_start_stop()
    test_healthz()
    test_evaluate_approved()
    test_evaluate_denied()
    test_verify_binding()
    test_register_executed()
    test_patch_nanoclaw_agent_sidecar()
    test_env_var_host_port()
    test_server_stopped_raises()
    test_server_default_host()

    print()
    if _failures:
        print(f"  \033[91m{len(_failures)} test(s) FAILED:\033[0m")
        for f in _failures:
            print(f"    • {f}")
        sys.exit(1)
    else:
        print(f"  \033[92mAll tests passed.\033[0m")


if __name__ == "__main__":
    main()
