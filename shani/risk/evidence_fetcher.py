"""
shani/risk/evidence_fetcher.py

EvidenceFetcher — Pull 型エビデンス取得レイヤー。

Problem:
    EvidenceItem.content はエージェントが直接書き込む Push 型。
    エージェントは任意の内容を content に挿入できるため、
    Shani 側では content の正確性を検証する手段がない。

Solution:
    EvidenceItem.raw_reference が設定されている場合、
    Shani 側が信頼済み SourceHandler を使ってコンテンツを取得し、
    エージェント提供の content を上書きする（Pull 型）。

    取得失敗・未登録スキームの場合は、source を
    "unverified_reference/{元ソース}" に変更し信頼度を降格する。

Components:
    FetchResult    — fetch 結果のコンテナ
    SourceHandler  — 特定スキームを処理するハンドラのプロトコル
    EvidenceStore  — Shani 側が事前登録したエビデンスの Key-Value ストア
    StoreHandler   — "store://" スキームを処理する組み込みハンドラ
    EvidenceFetcher — ハンドラを管理し EvidenceItem リストを解決するオーケストレータ
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..schemas.decision import EvidenceItem

# 未検証参照のソースプレフィックス（evidence.py の _SOURCE_TRUST_MAP に登録済み）
UNVERIFIED_PREFIX = "unverified_reference"

# 未解決参照に適用する信頼度の上限
_UNRESOLVED_CONFIDENCE_CAP = 0.3


# ---------------------------------------------------------------------------
# FetchResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FetchResult:
    """SourceHandler の fetch 結果。"""
    success: bool
    content: str | None = None
    error: str | None = None
    handler_name: str = "unknown"


# ---------------------------------------------------------------------------
# SourceHandler プロトコル
# ---------------------------------------------------------------------------

@runtime_checkable
class SourceHandler(Protocol):
    """特定の raw_reference スキームを処理するハンドラのインターフェース。"""

    @property
    def name(self) -> str:
        """このハンドラの識別名。"""
        ...

    def can_handle(self, reference: str) -> bool:
        """このハンドラが reference を処理できるかを返す。"""
        ...

    def fetch(self, reference: str) -> FetchResult:
        """reference からコンテンツを取得する。"""
        ...


# ---------------------------------------------------------------------------
# EvidenceStore
# ---------------------------------------------------------------------------

class EvidenceStore:
    """
    Shani 信頼済みエビデンスの Key-Value ストア。

    信頼済みシステム側が事前登録したエビデンスを保持する。
    エージェントは "store://<key>" 形式で参照できるが、
    コンテンツの書き込みは Shani 側のみが行える。
    """

    _SCHEME = "store://"

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def register(self, key: str, content: str) -> None:
        """信頼済みコンテンツをキーで登録する。"""
        if not key:
            raise ValueError("key must not be empty")
        self._store[key] = content

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __len__(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# StoreHandler — "store://" スキームのハンドラ
# ---------------------------------------------------------------------------

class StoreHandler:
    """EvidenceStore の "store://<key>" 参照を処理するハンドラ。"""

    _SCHEME = "store://"

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    @property
    def name(self) -> str:
        return "store"

    def can_handle(self, reference: str) -> bool:
        return reference.startswith(self._SCHEME)

    def fetch(self, reference: str) -> FetchResult:
        key = reference[len(self._SCHEME):]
        content = self._store.get(key)
        if content is None:
            return FetchResult(
                success=False,
                error=f"key '{key}' not found in EvidenceStore",
                handler_name=self.name,
            )
        return FetchResult(success=True, content=content, handler_name=self.name)


# ---------------------------------------------------------------------------
# EvidenceFetcher
# ---------------------------------------------------------------------------

class EvidenceFetcher:
    """
    EvidenceItem リストを解決するオーケストレータ。

    raw_reference が設定されている EvidenceItem を Pull 型に変換する。
    登録済みハンドラで取得成功 → content を上書き。
    取得失敗・未登録 → source を降格して信頼度を下げる。
    raw_reference が未設定 → 変更なし（後方互換）。
    """

    def __init__(self, handlers: list[SourceHandler] | None = None) -> None:
        self._handlers: list[SourceHandler] = list(handlers) if handlers else []

    def register_handler(self, handler: SourceHandler) -> None:
        """SourceHandler を登録する。"""
        self._handlers.append(handler)

    def resolve(self, evidence: list[EvidenceItem]) -> list[EvidenceItem]:
        """
        EvidenceItem リストを解決して返す。

        raw_reference が設定されているアイテムのみ処理する。
        """
        return [self._resolve_item(item) for item in evidence]

    def _resolve_item(self, item: EvidenceItem) -> EvidenceItem:
        if not item.raw_reference:
            return item

        handler = self._find_handler(item.raw_reference)
        if handler is None:
            return self._downgrade(item, f"no handler for reference '{item.raw_reference}'")

        result = handler.fetch(item.raw_reference)
        if not result.success:
            return self._downgrade(item, result.error or "fetch failed")

        # 取得成功 → content を信頼済みデータで上書き（Pull 型）
        return EvidenceItem(
            source=item.source,
            content=result.content,  # type: ignore[arg-type]
            confidence=item.confidence,
            raw_reference=item.raw_reference,
        )

    def _find_handler(self, reference: str) -> SourceHandler | None:
        for h in self._handlers:
            if h.can_handle(reference):
                return h
        return None

    def _downgrade(self, item: EvidenceItem, reason: str) -> EvidenceItem:
        """
        取得失敗時にエビデンスを降格する。

        source を "unverified_reference/{元ソース}" に変更し、
        信頼度を _UNRESOLVED_CONFIDENCE_CAP 以下に制限する。
        """
        degraded_source = f"{UNVERIFIED_PREFIX}/{item.source}"
        current_confidence = item.confidence if item.confidence is not None else 0.5
        capped_confidence = min(current_confidence, _UNRESOLVED_CONFIDENCE_CAP)

        return EvidenceItem(
            source=degraded_source,
            content=item.content,
            confidence=capped_confidence,
            raw_reference=item.raw_reference,
        )
