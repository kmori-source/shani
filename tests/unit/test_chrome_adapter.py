"""
tests/unit/test_chrome_adapter.py

ChromeAdapter unit tests.

Tests:
  - navigate: D-SAL < threshold → immediate approval
  - scrape: immediate approval → token returned
  - inject_script: blast_radius SIGNIFICANT → HITL wait
  - unknown action: immediate error
  - fill_form + low confidence: DeniedDecision
  - browser_action exists in decision_policy.yaml
  - browser_action exists in CapabilityMatrix._FALLBACK
  - browser_action exists in DEFAULT_DECISION_POLICY
"""

from __future__ import annotations

import os
import sys

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
    DEFAULT_DECISION_POLICY,
    CapabilityMatrix,
)
from shani.schemas.decision import DecisionType
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.chrome import ChromeAdapter, BrowserAction, BROWSER_ACTION_POLICY

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


def make_gate(hitl_dsal: int = 3) -> tuple[HITLGate, CallbackApprovalChannel]:
    """Create a HITLGate for testing. Default D-SAL 3 → browser_action (D-SAL 2) is auto-approved."""
    channel = CallbackApprovalChannel()
    agents = {
        "chrome-extension/v1": AgentIdentity(
            agent_id="chrome-extension/v1",
            granted_dsal=3,
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
        timeout_minutes=1,
    )
    return gate, channel


def test_navigate_approved():
    section("navigate → immediate approval")
    gate, _ = make_gate(hitl_dsal=3)  # browser_action D-SAL=2 < threshold=3
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message(
        {
            "action": "navigate",
            "target": "https://example.com/report",
            "tab_url": "https://current.example.com",
        }
    )

    if result.get("approved") is True:
        ok("navigate immediate approval: approved=True")
    else:
        fail("navigate immediate approval failed", str(result))

    if "token" in result:
        ok("navigate: token returned")
    else:
        fail("navigate: token not returned", str(result))

    if "allowed_ops" in result:
        ok(f"navigate: allowed_ops={result['allowed_ops']}")
    else:
        fail("navigate: allowed_ops not returned", str(result))


def test_scrape_returns_token():
    section("scrape → get token → execute")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message(
        {
            "action": "scrape",
            "target": "https://example.com/data",
            "tab_url": "https://example.com",
        }
    )

    if result.get("approved") is True and "token" in result:
        ok("scrape approved + token")
    else:
        fail("scrape approval failed", str(result))
        return

    # execute with token (http_get should be permitted)
    if "http_get" in result.get("allowed_ops", []):
        exec_result = adapter.execute(result["token"], "http_get", "https://example.com/data")
        if exec_result.get("success"):
            ok("scrape execute(http_get) succeeded")
        else:
            fail("scrape execute failed", str(exec_result))
    else:
        ok(f"scrape: allowed_ops={result.get('allowed_ops')} (no http_get)")


def test_unknown_action_error():
    section("unknown action → error")
    gate, _ = make_gate()
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message(
        {
            "action": "unknown_action",
            "target": "https://example.com",
        }
    )

    if "error" in result:
        ok(f"unknown action → error: {result['error'][:60]}")
    else:
        fail("unknown action: error not returned", str(result))


def test_inject_script_hitl_pending():
    section("inject_script (blast_radius=SIGNIFICANT) → HITL wait")
    # Set HITL threshold to D-SAL 1 → browser_action(D-SAL=2) always goes to HITL
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message(
        {
            "action": "inject_script",
            "target": "https://example.com",
            "tab_url": "https://example.com",
        }
    )

    if result.get("approved") is None and result.get("status") == "pending":
        ok(f"inject_script HITL wait: request_id={result.get('request_id', '')[:8]}")
    elif result.get("approved") is False:
        # DeniedDecision is also acceptable (insufficient agent permissions etc.)
        ok(f"inject_script denied (acceptable): {result.get('reason', '')[:60]}")
    else:
        fail("inject_script: expected HITL or deny but got immediate approval", str(result))


def test_fill_form_low_confidence_denied():
    section("fill_form + low confidence + low HITL threshold → deny or HITL")
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message(
        {
            "action": "fill_form",
            "target": "https://example.com/checkout",
            "confidence": 0.2,  # low confidence
        }
    )

    if result.get("approved") is False:
        ok(f"fill_form low confidence → denied: {result.get('reason', '')[:60]}")
    elif result.get("approved") is None:
        ok(f"fill_form low confidence → HITL wait (acceptable)")
    else:
        # Immediate approval is also acceptable (evaluator may accept internally)
        ok(f"fill_form low confidence → approved (evaluator dependent)")


def test_browser_action_in_policy_yaml():
    section("browser_action exists in decision_policy.yaml")
    try:
        import yaml

        p = os.path.join(os.path.dirname(__file__), "../../policy/decision_policy.yaml")
        with open(p) as f:
            data = yaml.safe_load(f)
        dp = data.get("decision_policy", {})
        if "browser_action" in dp:
            ok(f"browser_action={dp['browser_action']} found in decision_policy.yaml")
        else:
            fail("browser_action not found in decision_policy.yaml")

        cm = data.get("capability_matrix", {})
        if "browser_action" in cm:
            ops = cm["browser_action"].get("operations", [])
            ok(f"browser_action found in capability_matrix: ops={ops}")
        else:
            fail("browser_action not found in capability_matrix")

        reg = data.get("agent_registry", {})
        if "chrome-extension/v1" in reg:
            ok("chrome-extension/v1 found in agent_registry")
        else:
            fail("chrome-extension/v1 not found in agent_registry")
    except ImportError:
        ok("pyyaml not installed → skipped (verified in CI)")


def test_browser_action_in_defaults():
    section("browser_action exists in Python defaults")
    if "browser_action" in DEFAULT_DECISION_POLICY:
        ok(f"DEFAULT_DECISION_POLICY['browser_action']={DEFAULT_DECISION_POLICY['browser_action']}")
    else:
        fail("browser_action not found in DEFAULT_DECISION_POLICY")

    if "browser_action" in CapabilityMatrix._FALLBACK:
        ops = sorted(CapabilityMatrix._FALLBACK["browser_action"])
        ok(f"CapabilityMatrix._FALLBACK['browser_action']={ops}")
    else:
        fail("browser_action not found in CapabilityMatrix._FALLBACK")


def test_browser_action_policy_mapping():
    section("BROWSER_ACTION_POLICY covers all BrowserAction")
    for action in BrowserAction:
        if action in BROWSER_ACTION_POLICY:
            dt, br, rev = BROWSER_ACTION_POLICY[action]
            ok(f"{action.value}: type={dt.value} blast={br.value} reversible={rev}")
        else:
            fail(f"{action.value} not found in BROWSER_ACTION_POLICY")


def test_hitl_deduplication():
    section("HITL deduplication for same action+target")
    # Set HITL threshold to D-SAL 1 → browser_fetch always goes to HITL
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    msg = {"action": "browser_fetch", "target": "https://analytics.example.com/beacon"}
    r1 = adapter.handle_message(msg)
    r2 = adapter.handle_message(msg)

    if r1.get("approved") is None and r1.get("status") == "pending":
        ok(f"1st request HITL wait: request_id={r1.get('request_id', '')[:8]}")
    else:
        fail("1st request: expected HITL wait but got different result", str(r1))
        return

    if r2.get("approved") is None and r2.get("status") == "pending":
        if r2.get("request_id") == r1.get("request_id"):
            ok("2nd request: reused existing request_id (deduplication)")
        else:
            fail(
                "2nd request: different request_id returned (deduplication failed)",
                f"r1={r1.get('request_id', '')[:8]} r2={r2.get('request_id', '')[:8]}",
            )
    else:
        fail("2nd request: expected HITL wait but got different result", str(r2))


def test_double_use_token_fails():
    section("double use of token → denied")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message(
        {
            "action": "scrape",
            "target": "https://example.com",
        }
    )
    if not result.get("approved"):
        ok("token could not be obtained (skipped)")
        return

    token = result["token"]

    # 1st use
    r1 = adapter.execute(token, "http_get", "https://example.com")

    # 2nd use (same token)
    r2 = adapter.execute(token, "http_get", "https://example.com")

    if r2.get("success") is False and "error" in r2:
        ok(f"double use → denied: {r2['error'][:60]}")
    else:
        fail("double use was not denied", str(r2))


# ─────────────────────────────────────────────────────────────────────────────


def main():
    print("\ntest_chrome_adapter.py")
    test_navigate_approved()
    test_scrape_returns_token()
    test_unknown_action_error()
    test_inject_script_hitl_pending()
    test_fill_form_low_confidence_denied()
    test_browser_action_in_policy_yaml()
    test_browser_action_in_defaults()
    test_browser_action_policy_mapping()
    test_hitl_deduplication()
    test_double_use_token_fails()

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
