"""
Shani Chrome Extension Adapter.

Controls browser operation requests from Chrome extensions with Shani governance.

Flow:
    content.js / background.js
        ↓ message: {"action": "navigate", "target": "https://...", ...}
    ChromeAdapter.handle_message()
        ↓ builds DecisionProposal → gate.evaluate()
    Shani (HITLGate or ShaniEvaluator)
        ↓ D-SAL >= threshold → HITL wait or immediate approval
    ChromeAdapter
        ↓ ADO → capability token returned
    Chrome Extension
        ↓ POST /execute with token → action execution

Usage:
    from shani.adapters.chrome import ChromeAdapter, BrowserAction
    from shani.hitl import HITLGate

    adapter = ChromeAdapter(gate=hitl_gate, proposed_by="chrome-extension/v1")

    # Process message from Chrome extension
    result = adapter.handle_message({
        "action": "navigate",
        "target": "https://example.com",
        "tab_url": "https://current-page.com",
    })
    # → {"approved": True, "token": "...", "allowed_ops": [...]}
    # → {"approved": None, "request_id": "...", "status": "pending"}  (HITL)
    # → {"approved": False, "reason": "..."}  (denied)
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from ...schemas.decision import (
    BlastRadius,
    DecisionProposal,
    DecisionScope,
    DecisionType,
    EvidenceItem,
)
from ...core.evaluator import DeniedDecision, ShaniEvaluator
from ...hitl.approval.gate import HITLGate
from ...boundary.capability import ExecutionBoundary, Capability

logger = logging.getLogger("shani.adapter.chrome")

GovernanceGate = ShaniEvaluator | HITLGate


class BrowserAction(str, Enum):
    """Types of browser operations that Chrome extensions can request."""

    NAVIGATE = "navigate"
    SCRAPE = "scrape"
    SCREENSHOT = "screenshot"
    FILL_FORM = "fill_form"
    CLICK = "click"
    INJECT_SCRIPT = "inject_script"
    BROWSER_FETCH = "browser_fetch"  # external requests via fetch/XHR (Proxy intercept)


# Governance policy per BrowserAction
# (DecisionType, BlastRadius, reversibility)
BROWSER_ACTION_POLICY: dict[BrowserAction, tuple[DecisionType, BlastRadius, bool]] = {
    BrowserAction.NAVIGATE: (DecisionType.BROWSER_ACTION, BlastRadius.ISOLATED, True),
    BrowserAction.SCRAPE: (DecisionType.BROWSER_ACTION, BlastRadius.ISOLATED, True),
    BrowserAction.SCREENSHOT: (DecisionType.BROWSER_ACTION, BlastRadius.ISOLATED, True),
    BrowserAction.FILL_FORM: (DecisionType.BROWSER_ACTION, BlastRadius.LIMITED, True),
    BrowserAction.CLICK: (DecisionType.BROWSER_ACTION, BlastRadius.LIMITED, True),
    BrowserAction.INJECT_SCRIPT: (DecisionType.BROWSER_ACTION, BlastRadius.SIGNIFICANT, False),
    BrowserAction.BROWSER_FETCH: (DecisionType.BROWSER_ACTION, BlastRadius.LIMITED, True),
}


class ChromeAdapter:
    """
    Adapter that bridges messages from Chrome extensions to Shani governance.

    Intended to be called from an HTTP sidecar, but can also be
    used directly from Python.
    """

    def __init__(
        self,
        gate: GovernanceGate,
        proposed_by: str = "chrome-extension/v1",
        timeout_minutes: int = 10,
    ) -> None:
        self._gate = gate
        self._proposed_by = proposed_by
        self._timeout_minutes = timeout_minutes
        self._boundary = ExecutionBoundary(gate)

        # token → Capability (approved)
        self._caps: dict[str, Capability] = {}
        # request_id → DecisionProposal (pending HITL)
        self._pending_proposals: dict[str, DecisionProposal] = {}
        # dedup key "action:target" → request_id (for HITL deduplication)
        self._pending_dedup: dict[str, str] = {}
        self._lock = threading.Lock()

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """
        Processes an action request from a Chrome extension.

        Args:
            message: {
                "action": "navigate" | "scrape" | "screenshot" | "fill_form" | "click" | "inject_script" | "browser_fetch",
                "target": "https://...",      # target URL
                "tab_url": "https://...",     # current tab URL (context)
                "args": {...},                # action-specific arguments
                "description": "...",        # optional: description of intent
                "confidence": 0.8,           # optional: confidence level (0-1)
                "evidence": [...],           # optional: list of EvidenceItems
            }

        Returns:
            immediate approval: {"approved": True, "token": "...", "allowed_ops": [...], "expires_at": "..."}
            HITL pending:       {"approved": None, "request_id": "...", "status": "pending"}
            denied:             {"approved": False, "reason": "..."}
            error:              {"error": "..."}
        """
        raw_action = message.get("action", "")
        try:
            action = BrowserAction(raw_action)
        except ValueError:
            return {
                "error": f"Unknown browser action: '{raw_action}'. "
                f"Valid actions: {[a.value for a in BrowserAction]}"
            }

        target = message.get("target", "unknown")
        tab_url = message.get("tab_url", "")
        description = message.get("description") or f"Browser {action.value}: {target}"
        confidence = float(message.get("confidence", 0.8))

        decision_type, blast_radius, reversibility = BROWSER_ACTION_POLICY[action]

        evidence = [
            EvidenceItem(
                source="chrome-extension-context",
                content=f"Tab: {tab_url}" if tab_url else "Tab: unknown",
                confidence=0.7,
            )
        ]
        for e in message.get("evidence", []):
            evidence.append(
                EvidenceItem(
                    source=e.get("source", "chrome-extension"),
                    content=e.get("content", ""),
                    confidence=float(e.get("confidence", 0.8)),
                )
            )

        proposal = DecisionProposal(
            decision_type=decision_type,
            proposed_by=self._proposed_by,
            description=description,
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=evidence,
            confidence=confidence,
            reversibility=reversibility,
            blast_radius=blast_radius,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )

        # Check D-SAL and select immediate or HITL path
        effective_dsal = self._gate._get_effective_dsal(proposal)

        if effective_dsal < self._gate._threshold:
            # Immediate approval path
            result = self._gate.evaluate(proposal)
            if isinstance(result, DeniedDecision):
                logger.warning(
                    "Chrome action DENIED | action=%s target=%s reason=%s",
                    action.value,
                    target,
                    result.reason,
                )
                return {"approved": False, "reason": result.reason}

            cap = self._boundary.issue_capability(result, proposal)
            token = str(uuid.uuid4())
            with self._lock:
                self._caps[token] = cap

            logger.info(
                "Chrome action APPROVED | action=%s target=%s dsal=%s",
                action.value,
                target,
                result.authorized_dsal,
            )
            return {
                "approved": True,
                "token": token,
                "allowed_ops": sorted(cap._allowed),
                "expires_at": result.expires_at.isoformat(),
                "decision_id": result.decision_id[:8],
            }
        else:
            # HITL path（async）
            dedup_key = f"{action.value}:{target}"
            with self._lock:
                existing_id = self._pending_dedup.get(dedup_key)
            if existing_id:
                logger.info(
                    "Chrome action DEDUP HITL | action=%s target=%s → reusing %s",
                    action.value,
                    target,
                    existing_id,
                )
                return {"approved": None, "request_id": existing_id, "status": "pending"}

            try:
                request_id = self._gate.submit(proposal)
                with self._lock:
                    self._pending_proposals[request_id] = proposal
                    self._pending_dedup[dedup_key] = request_id
                logger.info(
                    "Chrome action PENDING HITL | action=%s target=%s request_id=%s",
                    action.value,
                    target,
                    request_id,
                )
                return {"approved": None, "request_id": request_id, "status": "pending"}
            except Exception as exc:
                return {"approved": False, "reason": str(exc)}

    def collect(self, request_id: str) -> dict[str, Any]:
        """
        Polls for the result of a pending HITL request.

        Returns:
            pending:  {"status": "pending"}
            approved: {"approved": True, "token": "...", ...}
            denied:   {"approved": False, "reason": "..."}
        """
        with self._lock:
            proposal = self._pending_proposals.get(request_id)

        try:
            result = self._gate.collect(request_id, proposal)
        except RuntimeError:
            return {"status": "pending"}
        except KeyError as exc:
            return {"error": str(exc)}

        if isinstance(result, DeniedDecision):
            with self._lock:
                self._pending_proposals.pop(request_id, None)
                self._pending_dedup = {
                    k: v for k, v in self._pending_dedup.items() if v != request_id
                }
            return {"approved": False, "reason": result.reason}

        # ADO → Capability → token
        cap = self._boundary.issue_capability(result, proposal)
        token = str(uuid.uuid4())
        with self._lock:
            self._caps[token] = cap
            self._pending_proposals.pop(request_id, None)
            self._pending_dedup = {k: v for k, v in self._pending_dedup.items() if v != request_id}

        return {
            "approved": True,
            "token": token,
            "allowed_ops": sorted(cap._allowed),
            "expires_at": result.expires_at.isoformat(),
            "decision_id": result.decision_id[:8],
        }

    def execute(
        self, token: str, operation: str, target: str, payload: dict | None = None
    ) -> dict[str, Any]:
        """
        Executes an action using an approved token (single-use).

        Args:
            token:     token received from handle_message() or collect()
            operation: "http_get" | "http_post"
            target:    target URL for execution
            payload:   body for http_post

        Returns:
            {"success": True, "result": ...}
            {"success": False, "error": "..."}
        """
        with self._lock:
            cap = self._caps.pop(token, None)

        if cap is None:
            return {"success": False, "error": "Invalid or already-used token"}

        try:
            if operation == "http_get":
                result = cap.http_get(target)
            elif operation == "http_post":
                result = cap.http_post(target, payload or {})
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}. "
                    f"browser_action supports: http_get, http_post",
                }
            return {"success": True, "result": result}
        except Exception as exc:
            return {"success": False, "error": str(exc), "type": type(exc).__name__}
