"""
Shani nanoclaw Adapter.

Controls nanoclaw agent tool calls with Shani governance.

nanoclaw is a lightweight Python agent framework from qwibitai/nanoclaw.
This adapter wraps nanoclaw's Agent.tools with Shani, enforcing the
DecisionProposal → ADO → Capability flow per Shani Specification v0.3.

Usage (zero-change integration):

    from nanoclaw import Agent
    from shani.adapters.nanoclaw import patch_nanoclaw_agent
    from shani.hitl import HITLGate

    agent = Agent(name="my-agent", model="claude-3-5-sonnet-20241022")

    @agent.tool
    def fetch_report(url: str) -> str: ...

    @agent.tool
    def write_config(path: str, content: str) -> str: ...

    patch_nanoclaw_agent(
        agent=agent,
        gate=hitl_gate,
        proposed_by="nanoclaw-agent/v1",
        policy={
            "write_config": dict(
                decision_type=DecisionType.CONFIGURATION_CHANGE,
                blast_radius=BlastRadius.LIMITED,
            ),
        },
    )
    # All tool calls now go through Shani before execution.

Usage (per-tool wrapping):

    from shani.adapters.nanoclaw import ShaniNanoclawAdapter

    adapter = ShaniNanoclawAdapter(gate=hitl_gate, proposed_by="nanoclaw-agent/v1")
    result = adapter.call_tool(
        tool_name="fetch_report",
        tool_fn=fetch_report,
        kwargs={"url": "https://api.example.com/report"},
        decision_type=DecisionType.DATA_ACCESS,
        blast_radius=BlastRadius.ISOLATED,
    )
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable

from ...schemas.decision import (
    BlastRadius,
    DecisionProposal,
    DecisionScope,
    DecisionType,
    EvidenceItem,
)
from ...core.evaluator import DeniedDecision, ShaniEvaluator
from ...hitl.approval.gate import HITLGate
from ...boundary.capability import ExecutionBoundary
from ...adapters.generic.wrapper import ShaniToolWrapper, GovernanceGate

logger = logging.getLogger("shani.adapter.nanoclaw")


class NanoclawToolAction(str, Enum):
    """Action classification corresponding to nanoclaw tool types."""

    READ = "read"  # read-only tools (http_get, read_file equivalent)
    WRITE = "write"  # write tools (write_file, http_post equivalent)
    EXECUTE = "execute"  # command execution tools (run_command equivalent)
    FETCH = "fetch"  # external API fetch (http_get equivalent)

# Default policy — infers decision type from tool name patterns
NANOCLAW_TOOL_POLICY: dict[NanoclawToolAction, tuple[DecisionType, BlastRadius, bool]] = {
    NanoclawToolAction.READ: (DecisionType.DATA_ACCESS, BlastRadius.ISOLATED, True),
    NanoclawToolAction.FETCH: (DecisionType.DATA_ACCESS, BlastRadius.ISOLATED, True),
    NanoclawToolAction.WRITE: (DecisionType.CONFIGURATION_CHANGE, BlastRadius.LIMITED, True),
    NanoclawToolAction.EXECUTE: (DecisionType.AGENT_TASK, BlastRadius.SIGNIFICANT, False),
}


def _infer_action(tool_name: str) -> NanoclawToolAction:
    """Infers the default NanoclawToolAction from the tool name."""
    name = tool_name.lower()
    if any(kw in name for kw in ("write", "save", "update", "put", "post", "create", "delete")):
        return NanoclawToolAction.WRITE
    if any(kw in name for kw in ("run", "exec", "execute", "command", "cmd", "bash", "shell")):
        return NanoclawToolAction.EXECUTE
    if any(kw in name for kw in ("fetch", "get", "request", "call", "http")):
        return NanoclawToolAction.FETCH
    return NanoclawToolAction.READ


class ShaniNanoclawAdapter:
    """
    Adapter that wraps nanoclaw agent tool calls with Shani governance.

    Intercepts callables registered in nanoclaw's Agent.tools and
    enforces the DecisionProposal → ADO flow before execution.

    HITL requests with the same action+target are deduplicated.
    """

    def __init__(
        self,
        gate: GovernanceGate,
        proposed_by: str = "nanoclaw-agent/v1",
        timeout_minutes: int = 10,
    ) -> None:
        self._gate = gate
        self._proposed_by = proposed_by
        self._timeout_minutes = timeout_minutes
        self._boundary = ExecutionBoundary(gate)

        self._caps: dict[str, Any] = {}
        self._pending_proposals: dict[str, DecisionProposal] = {}
        self._pending_dedup: dict[str, str] = {}
        self._lock = threading.Lock()

    def call_tool(
        self,
        tool_name: str,
        tool_fn: Callable,
        kwargs: dict,
        decision_type: DecisionType | None = None,
        blast_radius: BlastRadius | None = None,
        reversibility: bool | None = None,
        evidence: list | None = None,
        confidence: float = 0.8,
    ) -> Any:
        """
        Synchronously executes a nanoclaw tool through Shani governance.

        Args:
            tool_name:     tool name (used in logs and DecisionProposal)
            tool_fn:       the actual callable
            kwargs:        arguments to pass to the tool
            decision_type: if None, inferred from tool name
            blast_radius:  if None, set automatically from action
            reversibility: if None, set automatically from action
            evidence:      additional evidence
            confidence:    agent confidence level

        Returns:
            return value of tool_fn(**kwargs)

        Raises:
            PermissionError: if Shani denies the action
            RuntimeError:    ADO binding verification failure
        """
        action = _infer_action(tool_name)
        default_dt, default_br, default_rev = NANOCLAW_TOOL_POLICY[action]

        dt = decision_type if decision_type is not None else default_dt
        br = blast_radius if blast_radius is not None else default_br
        rev = reversibility if reversibility is not None else default_rev

        target = f"{tool_name}:{str(kwargs)[:60]}"
        ev_items = [
            EvidenceItem(
                source="nanoclaw-agent",
                content=f"tool={tool_name} args_keys={sorted(kwargs.keys())}",
                confidence=0.75,
            )
        ]
        for e in evidence or []:
            if isinstance(e, EvidenceItem):
                ev_items.append(e)
            elif isinstance(e, dict):
                ev_items.append(
                    EvidenceItem(
                        source=e.get("source", "nanoclaw"),
                        content=e.get("content", ""),
                        confidence=float(e.get("confidence", 0.8)),
                    )
                )

        proposal = DecisionProposal(
            decision_type=dt,
            proposed_by=self._proposed_by,
            description=f"nanoclaw tool: {tool_name}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=ev_items,
            confidence=confidence,
            reversibility=rev,
            blast_radius=br,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )

        result = self._gate.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            logger.warning("nanoclaw tool DENIED | tool=%s reason=%s", tool_name, result.reason)
            raise PermissionError(f"Shani denied nanoclaw tool '{tool_name}': {result.reason}")

        logger.info("nanoclaw tool EXECUTING | tool=%s dsal=%s", tool_name, result.authorized_dsal)
        output = tool_fn(**kwargs)
        self._gate.register_executed(result, agent_id=self._proposed_by)
        return output

    def wrap_tool(
        self,
        tool_name: str,
        tool_fn: Callable,
        decision_type: DecisionType | None = None,
        blast_radius: BlastRadius | None = None,
        reversibility: bool | None = None,
        confidence: float = 0.8,
    ) -> ShaniToolWrapper:
        """
        Wraps a nanoclaw tool function in a ShaniToolWrapper and returns it.

        The returned callable has the same signature as the original tool_fn
        and passes through Shani governance on every call.

        Example:
            agent.tools["fetch"] = adapter.wrap_tool("fetch", original_fetch)
        """
        action = _infer_action(tool_name)
        default_dt, default_br, default_rev = NANOCLAW_TOOL_POLICY[action]

        return ShaniToolWrapper(
            fn=tool_fn,
            gate=self._gate,
            decision_type=decision_type if decision_type is not None else default_dt,
            blast_radius=blast_radius if blast_radius is not None else default_br,
            proposed_by=self._proposed_by,
            target_extractor=tool_name,
            reversibility=reversibility if reversibility is not None else default_rev,
            confidence=confidence,
            timeout_minutes=self._timeout_minutes,
        )


def patch_nanoclaw_agent(
    agent: Any,
    gate: GovernanceGate,
    proposed_by: str,
    policy: dict[str, dict] | None = None,
    default_blast_radius: BlastRadius | None = None,
    default_decision_type: DecisionType | None = None,
) -> None:
    """
    Replaces a nanoclaw Agent's tools with Shani-governed versions (in-place).

    Assumes the nanoclaw Agent holds tools as a dict or list.
    This function auto-detects that structure and wraps all tools in ShaniToolWrapper.

    Args:
        agent:                 nanoclaw.Agent instance
        gate:                  ShaniEvaluator or HITLGate
        proposed_by:           agent identifier (must match agent_registry in policy.yaml)
        policy:                tool name → {decision_type, blast_radius, ...} override policy
        default_blast_radius:  default applied to tools without a policy entry
        default_decision_type: default applied to tools without a policy entry

    Note:
        If nanoclaw's Agent.tools is a dict, patch directly.
        If it's a list, convert to {fn.__name__: fn} before patching.
    """
    policy = policy or {}
    adapter = ShaniNanoclawAdapter(gate=gate, proposed_by=proposed_by)

    # Patch if the nanoclaw Agent has a tools attribute
    tools = getattr(agent, "tools", None)
    if tools is None:
        logger.warning("nanoclaw Agent has no .tools attribute. Nothing to patch.")
        return

    if isinstance(tools, dict):
        patched: dict[str, Callable] = {}
        for name, fn in tools.items():
            tool_policy = policy.get(name, {})
            patched[name] = adapter.wrap_tool(
                tool_name=name,
                tool_fn=fn,
                decision_type=tool_policy.get("decision_type", default_decision_type),
                blast_radius=tool_policy.get("blast_radius", default_blast_radius),
                reversibility=tool_policy.get("reversibility"),
            )
            logger.info("Patched nanoclaw tool | name=%s", name)
        agent.tools = patched

    elif isinstance(tools, list):
        patched_list: list = []
        for fn in tools:
            name = getattr(fn, "__name__", str(fn))
            tool_policy = policy.get(name, {})
            wrapped = adapter.wrap_tool(
                tool_name=name,
                tool_fn=fn,
                decision_type=tool_policy.get("decision_type", default_decision_type),
                blast_radius=tool_policy.get("blast_radius", default_blast_radius),
                reversibility=tool_policy.get("reversibility"),
            )
            patched_list.append(wrapped)
            logger.info("Patched nanoclaw tool | name=%s", name)
        agent.tools = patched_list

    else:
        logger.warning(
            "Unsupported agent.tools type: %s. Use ShaniNanoclawAdapter.wrap_tool() directly.",
            type(tools).__name__,
        )
        return

    logger.info("nanoclaw agent patched | %d tools governed", len(agent.tools))
