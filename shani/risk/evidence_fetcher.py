"""
shani/risk/evidence_fetcher.py

EvidenceFetcher — Pull-based evidence retrieval layer.

Problem:
    EvidenceItem.content is Push-based, written directly by the agent.
    Since agents can insert arbitrary content into content,
    Shani has no means to verify the accuracy of content.

Solution:
    When EvidenceItem.raw_reference is set,
    Shani retrieves the content using a trusted SourceHandler and
    overwrites the agent-provided content (Pull-based).

    On fetch failure or unregistered scheme, the source is changed to
    "unverified_reference/{original_source}" and the confidence is downgraded.

Components:
    FetchResult    — container for fetch results
    SourceHandler  — protocol for handlers that process specific schemes
    EvidenceStore  — Key-Value store for evidence pre-registered by Shani
    StoreHandler   — built-in handler for the "store://" scheme
    EvidenceFetcher — orchestrator that manages handlers and resolves EvidenceItem lists
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..schemas.decision import EvidenceItem

# Source prefix for unverified references (registered in evidence.py's _SOURCE_TRUST_MAP)
UNVERIFIED_PREFIX = "unverified_reference"

# Confidence cap applied to unresolved references
_UNRESOLVED_CONFIDENCE_CAP = 0.3


# ---------------------------------------------------------------------------
# FetchResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchResult:
    """Result of a SourceHandler fetch."""

    success: bool
    content: str | None = None
    error: str | None = None
    handler_name: str = "unknown"


# ---------------------------------------------------------------------------
# SourceHandler protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SourceHandler(Protocol):
    """Interface for handlers that process specific raw_reference schemes."""

    @property
    def name(self) -> str:
        """Identifying name of this handler."""
        ...

    def can_handle(self, reference: str) -> bool:
        """Returns whether this handler can process the given reference."""
        ...

    def fetch(self, reference: str) -> FetchResult:
        """Retrieves content from the reference."""
        ...


# ---------------------------------------------------------------------------
# EvidenceStore
# ---------------------------------------------------------------------------


class EvidenceStore:
    """
    Key-Value store for Shani trusted evidence.

    Holds evidence pre-registered by the trusted system side.
    Agents can reference entries via "store://<key>" format, but
    only Shani can write content to the store.
    """

    _SCHEME = "store://"

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def register(self, key: str, content: str) -> None:
        """Register trusted content under a key."""
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
# StoreHandler — handler for the "store://" scheme
# ---------------------------------------------------------------------------


class StoreHandler:
    """Handler for "store://<key>" references in EvidenceStore."""

    _SCHEME = "store://"

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    @property
    def name(self) -> str:
        return "store"

    def can_handle(self, reference: str) -> bool:
        return reference.startswith(self._SCHEME)

    def fetch(self, reference: str) -> FetchResult:
        key = reference[len(self._SCHEME) :]
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
    Orchestrator that resolves a list of EvidenceItems.

    Converts EvidenceItems with raw_reference set to Pull-based retrieval.
    Fetch success via registered handler → overwrites content.
    Fetch failure or unregistered → downgrades source and reduces confidence.
    raw_reference not set → no change (backward compatible).
    """

    def __init__(self, handlers: list[SourceHandler] | None = None) -> None:
        self._handlers: list[SourceHandler] = list(handlers) if handlers else []

    def register_handler(self, handler: SourceHandler) -> None:
        """Register a SourceHandler."""
        self._handlers.append(handler)

    def resolve(self, evidence: list[EvidenceItem]) -> list[EvidenceItem]:
        """
        Resolves and returns the list of EvidenceItems.

        Only processes items where raw_reference is set.
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

        # Fetch success → overwrite content with trusted data (Pull-based)
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
        Downgrades evidence on fetch failure.

        Changes source to "unverified_reference/{original_source}" and
        caps confidence to _UNRESOLVED_CONFIDENCE_CAP or below.
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
