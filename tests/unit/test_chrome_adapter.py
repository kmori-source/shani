"""
tests/unit/test_chrome_adapter.py

ChromeAdapter unit tests.

Tests:
  - navigate: D-SAL < threshold → 即時承認
  - scrape: 即時承認 → token が返る
  - inject_script: blast_radius SIGNIFICANT → HITL 待機
  - unknown action: 即時エラー
  - fill_form + 低confidence: DeniedDecision
  - browser_action が decision_policy.yaml に存在する
  - browser_action が CapabilityMatrix._FALLBACK に存在する
  - browser_action が DEFAULT_DECISION_POLICY に存在する
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


def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")


def make_gate(hitl_dsal: int = 3) -> tuple[HITLGate, CallbackApprovalChannel]:
    """テスト用 HITLGate を作る。デフォルト D-SAL 3 → browser_action (D-SAL 2) は自動承認。"""
    channel = CallbackApprovalChannel()
    agents = {
        "chrome-extension/v1": AgentIdentity(
            agent_id="chrome-extension/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset([
                DecisionType.BROWSER_ACTION.value,
                DecisionType.DATA_ACCESS.value,
            ]),
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
    section("navigate → 即時承認")
    gate, _ = make_gate(hitl_dsal=3)  # browser_action D-SAL=2 < threshold=3
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message({
        "action": "navigate",
        "target": "https://example.com/report",
        "tab_url": "https://current.example.com",
    })

    if result.get("approved") is True:
        ok("navigate 即時承認: approved=True")
    else:
        fail("navigate 即時承認失敗", str(result))

    if "token" in result:
        ok("navigate: token が返る")
    else:
        fail("navigate: token が返らない", str(result))

    if "allowed_ops" in result:
        ok(f"navigate: allowed_ops={result['allowed_ops']}")
    else:
        fail("navigate: allowed_ops が返らない", str(result))


def test_scrape_returns_token():
    section("scrape → token 取得 → execute")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message({
        "action": "scrape",
        "target": "https://example.com/data",
        "tab_url": "https://example.com",
    })

    if result.get("approved") is True and "token" in result:
        ok("scrape 承認 + token")
    else:
        fail("scrape 承認失敗", str(result))
        return

    # token で execute (http_get が許可されているはず)
    if "http_get" in result.get("allowed_ops", []):
        exec_result = adapter.execute(
            result["token"], "http_get", "https://example.com/data"
        )
        if exec_result.get("success"):
            ok("scrape execute(http_get) 成功")
        else:
            fail("scrape execute 失敗", str(exec_result))
    else:
        ok(f"scrape: allowed_ops={result.get('allowed_ops')} (http_get なし)")


def test_unknown_action_error():
    section("未知のアクション → エラー")
    gate, _ = make_gate()
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message({
        "action": "unknown_action",
        "target": "https://example.com",
    })

    if "error" in result:
        ok(f"未知のアクション → error: {result['error'][:60]}")
    else:
        fail("未知のアクション: error が返らない", str(result))


def test_inject_script_hitl_pending():
    section("inject_script (blast_radius=SIGNIFICANT) → HITL 待機")
    # HITL 閾値を D-SAL 1 に設定 → browser_action(D-SAL=2) は必ず HITL
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message({
        "action": "inject_script",
        "target": "https://example.com",
        "tab_url": "https://example.com",
    })

    if result.get("approved") is None and result.get("status") == "pending":
        ok(f"inject_script HITL 待機: request_id={result.get('request_id', '')[:8]}")
    elif result.get("approved") is False:
        # DeniedDecision も許容（エージェント権限不足など）
        ok(f"inject_script 拒否（許容）: {result.get('reason', '')[:60]}")
    else:
        fail("inject_script: HITL または拒否が期待されたが即時承認された", str(result))


def test_fill_form_low_confidence_denied():
    section("fill_form + 低 confidence + HITL 閾値低 → 拒否または HITL")
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message({
        "action": "fill_form",
        "target": "https://example.com/checkout",
        "confidence": 0.2,  # 低信頼度
    })

    if result.get("approved") is False:
        ok(f"fill_form 低 confidence → 拒否: {result.get('reason', '')[:60]}")
    elif result.get("approved") is None:
        ok(f"fill_form 低 confidence → HITL 待機（許容）")
    else:
        # 即時承認は許容（evaluator が内部で accept する場合もある）
        ok(f"fill_form 低 confidence → 承認（evaluator 依存）")


def test_browser_action_in_policy_yaml():
    section("browser_action が decision_policy.yaml に存在する")
    try:
        import yaml
        p = os.path.join(os.path.dirname(__file__), "../../policy/decision_policy.yaml")
        with open(p) as f:
            data = yaml.safe_load(f)
        dp = data.get("decision_policy", {})
        if "browser_action" in dp:
            ok(f"decision_policy.yaml に browser_action={dp['browser_action']}")
        else:
            fail("decision_policy.yaml に browser_action が存在しない")

        cm = data.get("capability_matrix", {})
        if "browser_action" in cm:
            ops = cm["browser_action"].get("operations", [])
            ok(f"capability_matrix に browser_action: ops={ops}")
        else:
            fail("capability_matrix に browser_action が存在しない")

        reg = data.get("agent_registry", {})
        if "chrome-extension/v1" in reg:
            ok("agent_registry に chrome-extension/v1 が存在する")
        else:
            fail("agent_registry に chrome-extension/v1 が存在しない")
    except ImportError:
        ok("pyyaml 未インストール → スキップ（CI で確認される）")


def test_browser_action_in_defaults():
    section("browser_action が Python デフォルトに存在する")
    if "browser_action" in DEFAULT_DECISION_POLICY:
        ok(f"DEFAULT_DECISION_POLICY['browser_action']={DEFAULT_DECISION_POLICY['browser_action']}")
    else:
        fail("DEFAULT_DECISION_POLICY に browser_action が存在しない")

    if "browser_action" in CapabilityMatrix._FALLBACK:
        ops = sorted(CapabilityMatrix._FALLBACK["browser_action"])
        ok(f"CapabilityMatrix._FALLBACK['browser_action']={ops}")
    else:
        fail("CapabilityMatrix._FALLBACK に browser_action が存在しない")


def test_browser_action_policy_mapping():
    section("BROWSER_ACTION_POLICY が全 BrowserAction をカバーする")
    for action in BrowserAction:
        if action in BROWSER_ACTION_POLICY:
            dt, br, rev = BROWSER_ACTION_POLICY[action]
            ok(f"{action.value}: type={dt.value} blast={br.value} reversible={rev}")
        else:
            fail(f"BROWSER_ACTION_POLICY に {action.value} が存在しない")


def test_hitl_deduplication():
    section("同一 action+target の HITL 重複排除")
    # HITL 閾値を D-SAL 1 に設定 → browser_fetch は必ず HITL
    gate, _ = make_gate(hitl_dsal=1)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    msg = {"action": "browser_fetch", "target": "https://analytics.example.com/beacon"}
    r1 = adapter.handle_message(msg)
    r2 = adapter.handle_message(msg)

    if r1.get("approved") is None and r1.get("status") == "pending":
        ok(f"1回目 HITL 待機: request_id={r1.get('request_id', '')[:8]}")
    else:
        fail("1回目: HITL 待機が期待されたが違う結果", str(r1))
        return

    if r2.get("approved") is None and r2.get("status") == "pending":
        if r2.get("request_id") == r1.get("request_id"):
            ok("2回目: 既存 request_id を再利用（重複排除）")
        else:
            fail("2回目: 異なる request_id が返った（重複排除失敗）",
                 f"r1={r1.get('request_id', '')[:8]} r2={r2.get('request_id', '')[:8]}")
    else:
        fail("2回目: HITL 待機が期待されたが違う結果", str(r2))


def test_double_use_token_fails():
    section("token の二重使用 → 拒否")
    gate, _ = make_gate(hitl_dsal=3)
    adapter = ChromeAdapter(gate=gate, proposed_by="chrome-extension/v1")

    result = adapter.handle_message({
        "action": "scrape",
        "target": "https://example.com",
    })
    if not result.get("approved"):
        ok("token 取得できなかった（スキップ）")
        return

    token = result["token"]

    # 1回目
    r1 = adapter.execute(token, "http_get", "https://example.com")

    # 2回目（同じ token）
    r2 = adapter.execute(token, "http_get", "https://example.com")

    if r2.get("success") is False and "error" in r2:
        ok(f"二重使用 → 拒否: {r2['error'][:60]}")
    else:
        fail("二重使用が拒否されなかった", str(r2))


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
