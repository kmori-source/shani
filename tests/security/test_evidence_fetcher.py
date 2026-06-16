"""
tests/security/test_evidence_fetcher.py

Tests for the Pull-type evidence retrieval layer (EvidenceFetcher).

① Basic operation of EvidenceStore
② StoreHandler fetch behavior (success and failure)
③ Pull-type conversion via EvidenceFetcher.resolve
④ Downgrade of unresolved references (source demotion, confidence cap)
⑤ Items without raw_reference pass through unchanged
⑥ Registration and operation of custom SourceHandler
⑦ Integration with RiskPipeline (resolved_evidence is reflected in evaluation)
⑧ unverified_reference is classified as SELF_REPORTED in evidence.py
"""

from __future__ import annotations

import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic
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

warnings.filterwarnings("ignore")

from datetime import datetime, timedelta, timezone

from shani.schemas.decision import (
    DecisionProposal,
    DecisionType,
    BlastRadius,
    DecisionScope,
    EvidenceItem,
)
from shani.risk import (
    EvidenceFetcher,
    EvidenceStore,
    StoreHandler,
    FetchResult,
    SourceHandler,
    RiskPipeline,
    SourceTrust,
    classify_source,
)
from shani.risk.evidence_fetcher import UNVERIFIED_PREFIX, _UNRESOLVED_CONFIDENCE_CAP

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
_failures = []


def ok(msg):
    print(f"  {PASS} {msg}")


def fail(msg, d=""):
    _failures.append(msg)
    print(f"  {FAIL} {msg}" + (f"\n      {d}" if d else ""))


def section(t):
    print(f"\n  ── {t}")


def future():
    return datetime.now(tz=timezone.utc) + timedelta(minutes=5)


def prop(**kw) -> DecisionProposal:
    defaults = dict(
        decision_type=DecisionType.REMEDIATION,
        proposed_by="a/v1",
        description="restart service on dev server",
        target="host:dev-01",
        scope=DecisionScope(),
        evidence=[],
        confidence=0.9,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        delegation=False,
        expires_at=future(),
    )
    defaults.update(kw)
    return DecisionProposal(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# ① Basic operation of EvidenceStore
# ─────────────────────────────────────────────────────────────────────────────


def test_evidence_store_basic():
    section("① Basic operation of EvidenceStore")
    store = EvidenceStore()
    assert len(store) == 0

    store.register("cpu_alert", "CPU usage at 95% for 5 minutes")
    assert "cpu_alert" in store
    assert store.get("cpu_alert") == "CPU usage at 95% for 5 minutes"
    assert len(store) == 1
    ok("register/get/contains/len work correctly")

    assert store.get("nonexistent") is None
    ok("nonexistent key returns None")

    try:
        store.register("", "content")
        fail("empty key should raise ValueError")
    except ValueError:
        ok("ValueError raised for empty key")


# ─────────────────────────────────────────────────────────────────────────────
# ② StoreHandler fetch behavior (success and failure)
# ─────────────────────────────────────────────────────────────────────────────


def test_store_handler_fetch():
    section("② StoreHandler fetch behavior")
    store = EvidenceStore()
    store.register("incident_42", "network latency spike detected by SIEM")
    handler = StoreHandler(store)

    assert handler.can_handle("store://incident_42")
    assert not handler.can_handle("file:///etc/passwd")
    assert not handler.can_handle("https://example.com")
    ok("can_handle correctly identifies scheme")

    result = handler.fetch("store://incident_42")
    assert result.success is True
    assert result.content == "network latency spike detected by SIEM"
    assert result.handler_name == "store"
    ok(f"fetch succeeded: content='{result.content[:30]}...'")

    result_miss = handler.fetch("store://nonexistent")
    assert result_miss.success is False
    assert result_miss.error is not None
    assert "nonexistent" in result_miss.error
    ok(f"fetch failed: error='{result_miss.error}'")


# ─────────────────────────────────────────────────────────────────────────────
# ③ Pull-type conversion via EvidenceFetcher.resolve
# ─────────────────────────────────────────────────────────────────────────────


def test_fetcher_pull_conversion():
    section("③ Pull-type conversion via EvidenceFetcher.resolve")
    store = EvidenceStore()
    store.register("alert_001", "SIEM: unauthorized access detected on prod-db")
    fetcher = EvidenceFetcher(handlers=[StoreHandler(store)])

    # Agent injects fabricated content, but it gets overwritten via raw_reference
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
    ok("agent-provided content was overwritten by trusted store content (Pull-type)")
    ok(f"  content: '{r.content}'")


# ─────────────────────────────────────────────────────────────────────────────
# ④ Downgrade of unresolved references
# ─────────────────────────────────────────────────────────────────────────────


def test_fetcher_downgrade_unresolved():
    section("④ Downgrade of unresolved references")
    fetcher = EvidenceFetcher()  # no handlers

    # Unregistered scheme
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
    ok(f"source demoted: '{r.source}'")
    ok(f"confidence capped: {r.confidence} ≤ {_UNRESOLVED_CONFIDENCE_CAP}")

    # StoreHandler registered but key does not exist
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
    ok("nonexistent store key is also demoted")

    # Already low confidence is preserved (when below cap)
    item3 = EvidenceItem(
        source="sensor",
        content="low conf",
        confidence=0.1,
        raw_reference="store://missing",
    )
    resolved3 = fetcher2.resolve([item3])
    r3 = resolved3[0]
    assert r3.confidence == 0.1  # min(0.1, 0.3) = 0.1
    ok("already low confidence is unchanged (min applied)")


# ─────────────────────────────────────────────────────────────────────────────
# ⑤ Items without raw_reference pass through unchanged
# ─────────────────────────────────────────────────────────────────────────────


def test_fetcher_passthrough_no_reference():
    section("⑤ Items without raw_reference pass through unchanged")
    fetcher = EvidenceFetcher()

    item = EvidenceItem(
        source="monitor",
        content="CPU at 90%",
        confidence=0.9,
        raw_reference=None,
    )
    resolved = fetcher.resolve([item])
    r = resolved[0]
    assert r is item  # same object (unchanged)
    ok("item with raw_reference=None passes through unchanged")

    # Mixed list of items
    items = [
        EvidenceItem(source="siem", content="alert", confidence=0.8, raw_reference=None),
        EvidenceItem(
            source="agent", content="fabricated", confidence=0.9, raw_reference="store://x"
        ),
    ]
    resolved_mixed = fetcher.resolve(items)
    assert resolved_mixed[0] is items[0]
    assert resolved_mixed[1].source == f"{UNVERIFIED_PREFIX}/agent"
    ok("in mixed list, raw_reference=None items unchanged, others demoted")


# ─────────────────────────────────────────────────────────────────────────────
# ⑥ Registration and operation of custom SourceHandler
# ─────────────────────────────────────────────────────────────────────────────


def test_custom_handler():
    section("⑥ Registration of custom SourceHandler")

    class InMemoryHandler:
        """In-memory handler for testing."""

        def __init__(self, data: dict[str, str]):
            self._data = data

        @property
        def name(self) -> str:
            return "inmemory"

        def can_handle(self, reference: str) -> bool:
            return reference.startswith("mem://")

        def fetch(self, reference: str) -> FetchResult:
            key = reference[len("mem://") :]
            if key in self._data:
                return FetchResult(success=True, content=self._data[key], handler_name=self.name)
            return FetchResult(
                success=False, error=f"key '{key}' not found", handler_name=self.name
            )

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
    ok("custom handler Pull fetch succeeded")

    # Verify compliance with SourceHandler protocol
    assert isinstance(handler, SourceHandler)
    ok("custom handler conforms to SourceHandler protocol")


# ─────────────────────────────────────────────────────────────────────────────
# ⑦ Integration with RiskPipeline
# ─────────────────────────────────────────────────────────────────────────────


def test_pipeline_integration():
    section("⑦ Integration with RiskPipeline")

    store = EvidenceStore()
    store.register("real_alert", "EDR: malware detected on prod-web-01")
    fetcher = EvidenceFetcher(handlers=[StoreHandler(store)])

    pipeline_pull = RiskPipeline(evidence_fetcher=fetcher)
    pipeline_push = RiskPipeline()  # default (no handlers)

    # Pull-type: raw_reference with successful store lookup → high-quality evidence
    evidence_pull = [
        EvidenceItem(
            source="edr",
            content="FABRICATED",  # agent-provided (ignored)
            confidence=0.95,
            raw_reference="store://real_alert",
        )
    ]

    # Push-type: no raw_reference, agent-provided as-is
    evidence_push = [
        EvidenceItem(
            source="edr",
            content="EDR: malware detected on prod-web-01",
            confidence=0.95,
            raw_reference=None,
        )
    ]

    result_pull = pipeline_pull.evaluate(prop(evidence=evidence_pull), base_dsal=2)
    result_push = pipeline_push.evaluate(prop(evidence=evidence_push), base_dsal=2)

    ok(f"Pull-type quality_score: {result_pull.evidence_eval.quality_score:.3f}")
    ok(f"Push-type quality_score: {result_push.evidence_eval.quality_score:.3f}")

    # Pull-type (resolved EDR source) should have higher evidence quality
    assert result_pull.evidence_eval.quality_score > 0.0
    ok("Pull-type pipeline operates correctly")

    # raw_reference with no handler → demoted to low quality
    evidence_unresolved = [
        EvidenceItem(
            source="edr",
            content="FABRICATED",
            confidence=0.95,
            raw_reference="store://missing",
        )
    ]
    pipeline_no_handler = RiskPipeline(
        evidence_fetcher=EvidenceFetcher(handlers=[StoreHandler(EvidenceStore())])
    )
    result_unresolved = pipeline_no_handler.evaluate(
        prop(evidence=evidence_unresolved), base_dsal=2
    )
    ok(f"unresolved reference quality_score: {result_unresolved.evidence_eval.quality_score:.3f}")
    assert result_unresolved.evidence_eval.quality_score < result_pull.evidence_eval.quality_score
    ok("unresolved references result in lower evidence quality")


# ─────────────────────────────────────────────────────────────────────────────
# ⑧ unverified_reference is classified as SELF_REPORTED
# ─────────────────────────────────────────────────────────────────────────────


def test_unverified_reference_trust_classification():
    section("⑧ unverified_reference source classified as SELF_REPORTED")

    trust = classify_source(f"{UNVERIFIED_PREFIX}/edr")
    assert trust == SourceTrust.SELF_REPORTED, f"expected SELF_REPORTED, got {trust}"
    ok(f"'{UNVERIFIED_PREFIX}/edr' → {trust.value}")

    trust2 = classify_source(f"{UNVERIFIED_PREFIX}/monitor")
    assert trust2 == SourceTrust.SELF_REPORTED
    ok(f"'{UNVERIFIED_PREFIX}/monitor' → {trust2.value}")

    # Original source keyword (edr/monitor) is unaffected
    trust3 = classify_source("edr")
    assert trust3 == SourceTrust.SYSTEM_SENSOR
    ok("original 'edr' is still SYSTEM_SENSOR")


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
