"""
Shani cowork Adapter — Claude API (Anthropic) tool_use governance.

cowork is a multi-agent coordination framework using Claude API's tool_use feature.
This adapter passes Claude API tool_use blocks through Shani governance before execution,
enforcing the DecisionProposal → ADO → Capability flow.

Dependency: anthropic package (optional). Can be used without importing it.

Flow:
    Claude API
        ↓ response.content[i].type == "tool_use"
    ShaniCoworkAdapter.execute_tool_use()
        ├─ builds DecisionProposal
        ├─ gate.evaluate()
        │     ├─ D-SAL check
        │     └─ HITL (if D-SAL >= threshold)
        └─ executes tool_fn(**tool_input) after approval

Usage (inside Claude API loop):

    import anthropic
    from shani.adapters.cowork import ShaniCoworkAdapter
    from shani.hitl import HITLGate

    adapter = ShaniCoworkAdapter(
        gate=hitl_gate,
        proposed_by="cowork-agent/v1",
        policy={
            "bash":       dict(decision_type=DecisionType.AGENT_TASK,          blast_radius=BlastRadius.SIGNIFICANT),
            "write_file": dict(decision_type=DecisionType.CONFIGURATION_CHANGE, blast_radius=BlastRadius.LIMITED),
            "read_file":  dict(decision_type=DecisionType.DATA_ACCESS,          blast_radius=BlastRadius.ISOLATED),
        },
    )

    client = anthropic.Anthropic()
    tools = [...]  # anthropic ToolParam list

    response = client.messages.create(
        model="claude-opus-4-7-20261001",
        tools=tools,
        messages=messages,
    )

    # Process tool_use blocks through Shani
    tool_results = adapter.process_response(response, tool_registry)

    # Append tool_results to next messages and continue
    messages.append({"role": "assistant", "content": response.content})
    messages.append({"role": "user", "content": tool_results})

Tool registry format:
    tool_registry = {
        "bash":       lambda input: subprocess.check_output(input["command"], shell=True),
        "read_file":  lambda input: open(input["path"]).read(),
        "write_file": lambda input: open(input["path"], "w").write(input["content"]),
    }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Any, Callable

from ...schemas.decision import (
    BlastRadius,
    DecisionProposal,
    DecisionScope,
    DecisionType,
    EvidenceItem,
)
from ...core.evaluator import DeniedDecision
from ...adapters.generic.wrapper import GovernanceGate

logger = logging.getLogger("shani.adapter.cowork")


@dataclass
class CoworkToolPolicy:
    """
    Shani governance policy for an individual tool.

    Configured per tool name registered in tool_registry.
    Tools without an entry use the default policy (TOOL_CALL / LIMITED).
    """

    decision_type: DecisionType = DecisionType.TOOL_CALL
    blast_radius: BlastRadius = BlastRadius.LIMITED
    reversibility: bool = True
    confidence_override: float | None = None


# Infer default policy from tool name patterns
_TOOL_PATTERNS: list[tuple[list[str], CoworkToolPolicy]] = [
    (
        ["bash", "shell", "exec", "run", "command", "cmd"],
        CoworkToolPolicy(DecisionType.AGENT_TASK, BlastRadius.SIGNIFICANT, False),
    ),
    (
        ["write", "save", "create", "update", "delete", "remove", "put", "post"],
        CoworkToolPolicy(DecisionType.CONFIGURATION_CHANGE, BlastRadius.LIMITED, True),
    ),
    (
        ["http", "request", "call", "api"],
        CoworkToolPolicy(DecisionType.NETWORK_ACTION, BlastRadius.LIMITED, True),
    ),
    (
        ["read", "get", "fetch", "list", "search", "find", "query"],
        CoworkToolPolicy(DecisionType.DATA_ACCESS, BlastRadius.ISOLATED, True),
    ),
]


def _infer_policy(tool_name: str) -> CoworkToolPolicy:
    """Infers the default CoworkToolPolicy from the tool name."""
    name = tool_name.lower()
    for keywords, policy in _TOOL_PATTERNS:
        if any(kw in name for kw in keywords):
            return policy
    return CoworkToolPolicy()  # default: TOOL_CALL / LIMITED


class ShaniCoworkAdapter:
    """
    Adapter that wraps Claude API (Anthropic) tool_use blocks with Shani governance.

    Passes tool_use execution through the Shani DecisionProposal flow
    in cowork multi-agent frameworks or code that directly uses the Claude API.

    Dependency on the anthropic package is runtime-only (not used in type hints).
    Can be imported in environments where anthropic is not installed.
    """

    def __init__(
        self,
        gate: GovernanceGate,
        proposed_by: str = "cowork-agent/v1",
        policy: dict[str, dict | CoworkToolPolicy] | None = None,
        timeout_minutes: int = 10,
        deny_on_unknown_tool: bool = False,
    ) -> None:
        """
        Args:
            gate:                 ShaniEvaluator or HITLGate
            proposed_by:          agent identifier
            policy:               tool name → CoworkToolPolicy or dict
            timeout_minutes:      ADO expiry (minutes)
            deny_on_unknown_tool: whether to deny tools not in the registry (default: False = warn and execute)
        """
        self._gate = gate
        self._proposed_by = proposed_by
        self._timeout_minutes = timeout_minutes
        self._deny_on_unknown = deny_on_unknown_tool

        self._policy: dict[str, CoworkToolPolicy] = {}
        for name, p in (policy or {}).items():
            if isinstance(p, CoworkToolPolicy):
                self._policy[name] = p
            elif isinstance(p, dict):
                self._policy[name] = CoworkToolPolicy(
                    decision_type=p.get("decision_type", DecisionType.TOOL_CALL),
                    blast_radius=p.get("blast_radius", BlastRadius.LIMITED),
                    reversibility=bool(p.get("reversibility", True)),
                    confidence_override=p.get("confidence_override"),
                )

    def _get_policy(self, tool_name: str) -> CoworkToolPolicy:
        return self._policy.get(tool_name) or _infer_policy(tool_name)

    def execute_tool_use(
        self,
        tool_use_block: Any,
        tool_fn: Callable,
        context: str | None = None,
        confidence: float = 0.85,
    ) -> Any:
        """
        Executes a single tool_use block through Shani.

        Args:
            tool_use_block: anthropic ToolUseBlock (object with .name, .input, .id)
                            or dict {"name": ..., "input": ..., "id": ...}
            tool_fn:        the actual tool implementation callable (receives input dict)
            context:        Claude's thinking text (used as evidence)
            confidence:     execution confidence level

        Returns:
            return value of tool_fn(tool_use_block.input)

        Raises:
            PermissionError: if Shani denies the action
        """
        if isinstance(tool_use_block, dict):
            tool_name = tool_use_block["name"]
            tool_input = tool_use_block.get("input", {})
            tool_id = tool_use_block.get("id", "unknown")
        else:
            tool_name = tool_use_block.name
            tool_input = tool_use_block.input
            tool_id = getattr(tool_use_block, "id", "unknown")

        pol = self._get_policy(tool_name)
        target = f"{tool_name}:{str(tool_input)[:80]}"

        evidence: list[EvidenceItem] = [
            EvidenceItem(
                source="claude-api-tool-use",
                content=f"tool_use_id={tool_id} name={tool_name}",
                confidence=0.9,
            )
        ]
        if context:
            evidence.append(
                EvidenceItem(
                    source="claude-thinking",
                    content=context[:200],
                    confidence=0.7,
                )
            )

        proposal = DecisionProposal(
            decision_type=pol.decision_type,
            proposed_by=self._proposed_by,
            description=f"cowork tool_use: {tool_name}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=evidence,
            confidence=pol.confidence_override
            if pol.confidence_override is not None
            else confidence,
            reversibility=pol.reversibility,
            blast_radius=pol.blast_radius,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )

        result = self._gate.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            logger.warning("cowork tool_use DENIED | tool=%s reason=%s", tool_name, result.reason)
            raise PermissionError(f"Shani denied cowork tool '{tool_name}': {result.reason}")

        logger.info(
            "cowork tool_use EXECUTING | tool=%s dsal=%s", tool_name, result.authorized_dsal
        )
        output = tool_fn(tool_input)
        self._gate.register_executed(result, agent_id=self._proposed_by)
        return output

    def process_response(
        self,
        response: Any,
        tool_registry: dict[str, Callable],
        context: str | None = None,
    ) -> list[dict]:
        """
        Processes all tool_use blocks in a Claude API response through Shani.

        Args:
            response:       anthropic Messages response object
                            (.content is a list of blocks)
            tool_registry:  {"tool_name": callable} dict
            context:        Claude's thinking text (evidence)

        Returns:
            list of tool_result content blocks (to append to the next user message)

        Example:
            messages.append({"role": "assistant", "content": response.content})
            tool_results = adapter.process_response(response, tool_registry)
            messages.append({"role": "user", "content": tool_results})
        """
        tool_results: list[dict] = []

        content = (
            getattr(response, "content", response) if not isinstance(response, list) else response
        )

        for block in content:
            block_type = (
                block.get("type") if isinstance(block, dict) else getattr(block, "type", None)
            )
            if block_type != "tool_use":
                continue

            if isinstance(block, dict):
                tool_name = block["name"]
                tool_id = block.get("id", "unknown")
            else:
                tool_name = block.name
                tool_id = getattr(block, "id", "unknown")

            tool_fn = tool_registry.get(tool_name)
            if tool_fn is None:
                if self._deny_on_unknown:
                    logger.error(
                        "Unknown tool '%s' — denied (deny_on_unknown_tool=True)", tool_name
                    )
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "is_error": True,
                            "content": f"Unknown tool: {tool_name}",
                        }
                    )
                    continue
                else:
                    logger.warning("Unknown tool '%s' — not in registry, skipping", tool_name)
                    continue

            try:
                output = self.execute_tool_use(
                    tool_use_block=block,
                    tool_fn=tool_fn,
                    context=context,
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": str(output),
                    }
                )
            except PermissionError as exc:
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "is_error": True,
                        "content": str(exc),
                    }
                )

        return tool_results

    def wrap_tool_registry(
        self,
        tool_registry: dict[str, Callable],
    ) -> dict[str, Callable]:
        """
        Converts an entire tool registry to Shani-governed versions and returns it.

        Returns governed_fn in place of the original callable.
        governed_fn takes (tool_input: dict) as its argument and passes through Shani.

        Example:
            governed_registry = adapter.wrap_tool_registry(tool_registry)
            # all callables in governed_registry are executed only after Shani approval
        """
        governed: dict[str, Callable] = {}
        for name, fn in tool_registry.items():
            # bind via closure
            def make_governed(tool_name: str, tool_func: Callable) -> Callable:
                def governed_fn(tool_input: dict, _context: str | None = None) -> Any:
                    return self.execute_tool_use(
                        tool_use_block={"name": tool_name, "input": tool_input, "id": "wrapped"},
                        tool_fn=tool_func,
                        context=_context,
                    )

                governed_fn.__name__ = f"shani_governed_{tool_name}"
                return governed_fn

            governed[name] = make_governed(name, fn)
            logger.info("Wrapped cowork tool | name=%s", name)
        return governed
