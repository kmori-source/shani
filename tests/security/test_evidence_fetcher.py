"""
tests/security/test_evidence_fetcher.py

Tests for Pull 型エビデンス取得レイヤー（EvidenceFetcher）。

① EvidenceStore の基本動作
② StoreHandler の fetch 動作（成功・失敗）
③ EvidenceFetcher.resolve の Pull 型変換
④ 未解決参照のダウングレード（source 降格・confidence キャップ）
⑤ raw_reference 未設定のアイテムはそのまま通過
⑥ カスタム SourceHandler の登録と動作
⑦ RiskPipeline との統合（resolved_evidence が評価に反映される）
⑧ unverified_reference が evidence.py の SELF_REPORTED に分類される
"""
from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location("_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"))
    _mod = _iu.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel","Field","field_validator","model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings; warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone

from shani.schemas.decision import (
    DecisionProposal, DecisionType, BlastRadius, DecisionScope, EvidenceItem
)
from shani.risk import (
    EvidenceFetcher, EvidenceStore, StoreHandler, FetchResult, SourceHandler,
    RiskPipeline, SourceTrust, classify_source,
)
from shani.risk.evidence_fetcher import UNVERIFIED_PREFIX, _UNRESOLVED_CONFIDENCE_CAP

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []

def ok(msg): print(f"  {PASS} {msg}")
def fail(msg, d=""): _failures.append(msg); print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))
def section(t): print(f"\n  ── {t}")

def future(): return datetime.now(tz=timezone.utc) + timedelta(minutes=5)

def prop(**kw) -> DecisionProposal:
    defaults = dict(
        decision_type=DecisionType.REMEDIATION, proposed_by="a/v1",
        description="restart service on dev server", target="host:dev-01",
        scope=DecisionScope(), evidence=[],
        confidence=0.9, reversibility=True, blast_radius=BlastRadius.LIMITED,
        delegation=False, expires_at=future(),
    )
    defaults.update(kw)
    return DecisionProposal(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# ① EvidenceStore の基本動作
# ─────────────────────────────────────────────────────────────────────────────

def test_evidence_store_basic():
    section("① EvidenceStore の基本動作")
    store = EvidenceStore()
    assert len(store) == 0

    store.register("cpu_alert", "CPU usage at 95% for 5 minutes")
    assert "cpu_alert" in store
    assert store.get("cpu_alert") == "CPU usage at 95% for 5 minutes"
    assert len(store) == 1
    ok("register/get/contains/len が正常動作")

    assert store.get("nonexistent") is None
    ok("存在しないキーは None を返す")

    try:
        store.register("", "content")
        fail("空キーは ValueError を送出するべき")
    except ValueError:
        ok("空キーに対して ValueError を送出")


# ─────────────────────────────────────────────────────────────────────────────
# ② StoreHandler の fetch 動作（成功・失敗）
# ─────────────────────────────────────────────────────────────────────────────

def test_store_handler_fetch():
    section("② StoreHandler の fetch 動作")
    store = EvidenceStore()
    store.register("incident_42", "network latency spike detected by SIEM")
    handler = StoreHandler(store)

    assert handler.can_handle("store://incident_42")
    assert not handler.can_handle("file:///etc/passwd")
    assert not handler.can_handle("https://example.com")
    ok("can_handle がスキームを正しく判定")

    result = handler.fetch("store://incident_42")
    assert result.success is True
    assert result.content == "network latency spike detected by SIEM"
    assert result.handler_name == "store"
    ok(f"fetch 成功: content='{result.content[:30]}...'")

    result_miss = handler.fetch("store://nonexistent")
    assert result_miss.success is False
    assert result_miss.error is not None
    assert "nonexistent" in result_miss.error
    ok(f"fetch 失敗: error='{result_miss.error}'")


# ─────────────────────────────────────────────────────────────────────────────
# ③ EvidenceFetcher.resolve の Pull 型変換
# ─────────────────────────────────────────────────────────────────────────────

def test_fetcher_pull_conversion():
    section("③ EvidenceFetcher.resolve の Pull 型変換")
    store = EvidenceStore()
    store.register("alert_001", "SIEM: unauthorized access detected on prod-db")
    fetcher = EvidenceFetcher(handlers=[StoreHandler(store)])

    # エージェントは fabricated な content を投入しているが raw_reference で上書きされる
    item = EvidenceItem(
        source="siem",
        content="FABRICATED CONTENT FROM AGENT",
        confidence=0.9,
        raw_reference="store://alert_001",
    )
    resolved = fetcher.resolve([item])
    assert len(resolved) == 1
    r = resolved[0]
    assert r.content == "SIEM: unauthorized access detected on prod-db"
    assert r.source == "siem"
    assert r.confidence == 0.9
    assert r.raw_reference == "store://alert_001"
    ok("エージェント提供 content が信頼済みストア内容で上書きされた（Pull 型）")
    ok(f"  content: '{r.content}'")


# ─────────────────────────────────────────────────────────────────────────────
# ④ 未解決参照のダウングレード
# ─────────────────────────────────────────────────────────────────────────────

def test_fetcher_downgrade_unresolved():
    section("④ 未解決参照のダウングレード")
    fetcher = EvidenceFetcher()  # ハンドラなし

    # 未登録スキーム
    item = EvidenceItem(
        source="edr",
        content="agent fabricated content",
        confidence=0.95,
        raw_reference="custom://unknown-scheme",
    )
    resolved = fetcher.resolve([item])
    r = resolved[0]

    assert r.source == f"{UNVERIFIED_PREFIX}/edr"
    assert r.confidence <= _UNRESOLVED_CONFIDENCE_CAP
    ok(f"source が降格: '{r.source}'")
    ok(f"confidence がキャップ: {r.confidence} ≤ {_UNRESOLVED_CONFIDENCE_CAP}")

    # StoreHandler が登録されているが存在しないキー
    store = EvidenceStore()
    fetcher2 = EvidenceFetcher(handlers=[StoreHandler(store)])
    item2 = EvidenceItem(
        source="monitor",
        content="fabricated",
        confidence=0.8,
        raw_reference="store://missing_key",
    )
    resolved2 = fetcher2.resolve([item2])
    r2 = resolved2[0]
    assert r2.source == f"{UNVERIFIED_PREFIX}/monitor"
    assert r2.confidence <= _UNRESOLVED_CONFIDENCE_CAP
    ok("存在しないストアキーも降格される")

    # 既に低い confidence はそのまま（キャップより低い場合）
    item3 = EvidenceItem(
        source="sensor",
        content="low conf",
        confidence=0.1,
        raw_reference="store://missing",
    )
    resolved3 = fetcher2.resolve([item3])
    r3 = resolved3[0]
    assert r3.confidence == 0.1  # min(0.1, 0.3) = 0.1
    ok("既に低い confidence は変更されない（min 適用）")


# ─────────────────────────────────────────────────────────────────────────────
# ⑤ raw_reference 未設定のアイテムはそのまま通過
# ─────────────────────────────────────────────────────────────────────────────

def test_fetcher_passthrough_no_reference():
    section("⑤ raw_reference 未設定のアイテムは変更なし")
    fetcher = EvidenceFetcher()

    item = EvidenceItem(
        source="monitor",
        content="CPU at 90%",
        confidence=0.9,
        raw_reference=None,
    )
    resolved = fetcher.resolve([item])
    r = resolved[0]
    assert r is item  # 同一オブジェクト（変更なし）
    ok("raw_reference=None のアイテムは変更されずに通過")

    # 複数アイテムの混在
    items = [
        EvidenceItem(source="siem", content="alert", confidence=0.8, raw_reference=None),
        EvidenceItem(source="agent", content="fabricated", confidence=0.9, raw_reference="store://x"),
    ]
    resolved_mixed = fetcher.resolve(items)
    assert resolved_mixed[0] is items[0]
    assert resolved_mixed[1].source == f"{UNVERIFIED_PREFIX}/agent"
    ok("混在リストでも raw_reference=None は変更なし、設定済みは降格")


# ─────────────────────────────────────────────────────────────────────────────
# ⑥ カスタム SourceHandler の登録と動作
# ─────────────────────────────────────────────────────────────────────────────

def test_custom_handler():
    section("⑥ カスタム SourceHandler の登録")

    class InMemoryHandler:
        """テスト用インメモリハンドラ。"""
        def __init__(self, data: dict[str, str]):
            self._data = data

        @property
        def name(self) -> str:
            return "inmemory"

        def can_handle(self, reference: str) -> bool:
            return reference.startswith("mem://")

        def fetch(self, reference: str) -> FetchResult:
            key = reference[len("mem://"):]
            if key in self._data:
                return FetchResult(success=True, content=self._data[key], handler_name=self.name)
            return FetchResult(success=False, error=f"key '{key}' not found", handler_name=self.name)

    handler = InMemoryHandler({"key1": "trusted content from memory"})
    fetcher = EvidenceFetcher()
    fetcher.register_handler(handler)

    item = EvidenceItem(
        source="monitor",
        content="agent fabricated",
        confidence=0.7,
        raw_reference="mem://key1",
    )
    resolved = fetcher.resolve([item])
    r = resolved[0]
    assert r.content == "trusted content from memory"
    assert r.source == "monitor"
    ok("カスタムハンドラで Pull 取得成功")

    # SourceHandler プロトコルに準拠していることを確認
    assert isinstance(handler, SourceHandler)
    ok("カスタムハンドラが SourceHandler プロトコルに準拠")


# ─────────────────────────────────────────────────────────────────────────────
# ⑦ RiskPipeline との統合
# ─────────────────────────────────────────────────────────────────────────────

def test_pipeline_integration():
    section("⑦ RiskPipeline との統合")

    store = EvidenceStore()
    store.register("real_alert", "EDR: malware detected on prod-web-01")
    fetcher = EvidenceFetcher(handlers=[StoreHandler(store)])

    pipeline_pull = RiskPipeline(evidence_fetcher=fetcher)
    pipeline_push = RiskPipeline()  # デフォルト（ハンドラなし）

    # Pull 型: raw_reference ありでストア参照成功 → 高品質エビデンス
    evidence_pull = [EvidenceItem(
        source="edr",
        content="FABRICATED",  # エージェント提供（無視される）
        confidence=0.95,
        raw_reference="store://real_alert",
    )]

    # Push 型: raw_reference なし、エージェント提供のまま
    evidence_push = [EvidenceItem(
        source="edr",
        content="EDR: malware detected on prod-web-01",
        confidence=0.95,
        raw_reference=None,
    )]

    result_pull = pipeline_pull.evaluate(prop(evidence=evidence_pull), base_dsal=2)
    result_push = pipeline_push.evaluate(prop(evidence=evidence_push), base_dsal=2)

    ok(f"Pull 型 quality_score: {result_pull.evidence_eval.quality_score:.3f}")
    ok(f"Push 型 quality_score: {result_push.evidence_eval.quality_score:.3f}")

    # Pull 型（解決済み EDR ソース）はエビデンス品質が高いはず
    assert result_pull.evidence_eval.quality_score > 0.0
    ok("Pull 型パイプラインが正常に動作")

    # ハンドラなしで raw_reference あり → 降格されて低品質
    evidence_unresolved = [EvidenceItem(
        source="edr",
        content="FABRICATED",
        confidence=0.95,
        raw_reference="store://missing",
    )]
    pipeline_no_handler = RiskPipeline(evidence_fetcher=EvidenceFetcher(handlers=[StoreHandler(EvidenceStore())]))
    result_unresolved = pipeline_no_handler.evaluate(prop(evidence=evidence_unresolved), base_dsal=2)
    ok(f"未解決参照 quality_score: {result_unresolved.evidence_eval.quality_score:.3f}")
    assert result_unresolved.evidence_eval.quality_score < result_pull.evidence_eval.quality_score
    ok("未解決参照はエビデンス品質が低下する")


# ─────────────────────────────────────────────────────────────────────────────
# ⑧ unverified_reference が SELF_REPORTED に分類される
# ─────────────────────────────────────────────────────────────────────────────

def test_unverified_reference_trust_classification():
    section("⑧ unverified_reference ソースが SELF_REPORTED に分類")

    trust = classify_source(f"{UNVERIFIED_PREFIX}/edr")
    assert trust == SourceTrust.SELF_REPORTED, f"expected SELF_REPORTED, got {trust}"
    ok(f"'{UNVERIFIED_PREFIX}/edr' → {trust.value}")

    trust2 = classify_source(f"{UNVERIFIED_PREFIX}/monitor")
    assert trust2 == SourceTrust.SELF_REPORTED
    ok(f"'{UNVERIFIED_PREFIX}/monitor' → {trust2.value}")

    # 元のソースキーワード（edr/monitor）は影響しない
    trust3 = classify_source("edr")
    assert trust3 == SourceTrust.SYSTEM_SENSOR
    ok("元の 'edr' は依然 SYSTEM_SENSOR")


# ─────────────────────────────────────────────────────────────────────────────
# runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nEvidenceFetcher Security Tests")
    print("=" * 50)

    test_evidence_store_basic()
    test_store_handler_fetch()
    test_fetcher_pull_conversion()
    test_fetcher_downgrade_unresolved()
    test_fetcher_passthrough_no_reference()
    test_custom_handler()
    test_pipeline_integration()
    test_unverified_reference_trust_classification()

    print("\n" + "=" * 50)
    if _failures:
        print(f"\033[91m{len(_failures)} test(s) FAILED:\033[0m")
        for f in _failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print(f"\033[92mAll tests PASSED\033[0m")
