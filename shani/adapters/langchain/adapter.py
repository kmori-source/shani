"""
Shani LangChain Adapter.

Wraps LangChain BaseTool subclasses with Shani governance.
The original tool class is NOT modified.

Usage (drop-in):

    from langchain.tools import ShellTool
    from shani.adapters.langchain import ShaniLangChainTool

    shell_tool = ShellTool()

    governed_shell = ShaniLangChainTool(
        tool=shell_tool,
        gate=hitl_gate,
        decision_type=DecisionType.REMEDIATION,
        blast_radius=BlastRadius.SIGNIFICANT,
        proposed_by="langchain-agent/v1",
        target_extractor=lambda inp: f"shell:{inp[:40]}",
    )

    # Use governed_shell anywhere you'd use shell_tool.
    # It has the same name, description, and args_schema.

Or use the patch function to govern an entire agent's toolset:

    tools = [tool1, tool2, tool3]
    governed_tools = patch_langchain_tools(
        tools=tools,
        gate=hitl_gate,
        proposed_by="my-agent/v1",
        policy={
            "ShellTool": dict(decision_type=DecisionType.REMEDIATION, blast_radius=BlastRadius.SIGNIFICANT),
            "WriteFileTool": dict(decision_type=DecisionType.CONFIGURATION_CHANGE, blast_radius=BlastRadius.LIMITED),
        }
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ...schemas.decision import (
    DecisionProposal,
    DecisionType,
    BlastRadius,
    DecisionScope,
)
from ...core.evaluator import DeniedDecision
from ...hitl.approval.gate import HITLGate
from ...adapters.generic.wrapper import GovernanceGate

logger = logging.getLogger("shani.adapter.langchain")


class ShaniLangChainTool:
    """
    A governed wrapper around a LangChain BaseTool.

    Presents the same interface as the wrapped tool:
        - .name
        - .description
        - .run(tool_input)
        - .arun(tool_input)  [async]

    Every call goes through Shani before reaching the original tool.
    """

    def __init__(
        self,
        tool: Any,  # LangChain BaseTool — not imported to avoid hard dependency
        gate: GovernanceGate,
        decision_type: DecisionType,
        blast_radius: BlastRadius,
        proposed_by: str,
        target_extractor: Callable[[str | dict], str] | None = None,
        evidence_extractor: Callable[[str | dict], list] | None = None,
        confidence: float = 0.8,
        reversibility: bool = True,
    ) -> None:
        self._tool = tool
        self._gate = gate
        self._decision_type = decision_type
        self._blast_radius = blast_radius
        self._proposed_by = proposed_by
        self._target_extractor = target_extractor
        self._evidence_extractor = evidence_extractor
        self._confidence = confidence
        self._reversibility = reversibility

    @property
    def name(self) -> str:
        return self._tool.name

    @property
    def description(self) -> str:
        return f"[Shani-governed] {self._tool.description}"

    @property
    def args_schema(self) -> Any:
        return getattr(self._tool, "args_schema", None)

    def run(self, tool_input: str | dict, **kwargs) -> str:
        proposal = self._build_proposal(tool_input)
        result = self._gate.evaluate(proposal)

        if isinstance(result, DeniedDecision):
            raise PermissionError(f"Shani denied '{self._tool.name}': {result.reason}")

        logger.info(
            "LangChain tool executing | tool=%s dsal=%s", self._tool.name, result.authorized_dsal
        )
        output = self._tool.run(tool_input, **kwargs)
        self._gate.register_executed(result, agent_id=self._proposed_by)
        return output

    async def arun(self, tool_input: str | dict, **kwargs) -> str:
        """Async version — delegates to sync run (override for true async)."""
        return self.run(tool_input, **kwargs)

    def _build_proposal(self, tool_input: str | dict) -> DecisionProposal:
        if self._target_extractor:
            target = self._target_extractor(tool_input)
        elif isinstance(tool_input, str):
            target = f"{self._tool.name}:{tool_input[:60]}"
        else:
            target = f"{self._tool.name}:dict-input"

        return DecisionProposal(
            decision_type=self._decision_type,
            proposed_by=self._proposed_by,
            description=f"LangChain tool: {self._tool.name}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=self._evidence_extractor(tool_input) if self._evidence_extractor else [],
            confidence=self._confidence,
            reversibility=self._reversibility,
            blast_radius=self._blast_radius,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=15),
        )


def patch_langchain_tools(
    tools: list[Any],
    gate: GovernanceGate,
    proposed_by: str,
    policy: dict[str, dict] | None = None,
    default_dsal: int = 1,
    default_blast_radius: BlastRadius = BlastRadius.LIMITED,
    default_decision_type: DecisionType = DecisionType.REMEDIATION,
) -> list[Any]:
    """
    Wrap an entire list of LangChain tools with Shani governance.

    Tools not in the policy dict get default governance settings.
    Tools in the policy dict get their specific settings.

    This is the "add-on without modifying agent code" entry point.
    Your agent is initialized with governed_tools instead of tools.
    The agent code doesn't change.

    Example:
        tools = load_my_tools()
        governed = patch_langchain_tools(tools, gate=hitl_gate, proposed_by="my-agent/v1")
        agent = initialize_agent(governed, llm, ...)
    """
    governed = []
    policy = policy or {}

    for tool in tools:
        tool_policy = policy.get(tool.name, policy.get(type(tool).__name__, {}))
        governed.append(
            ShaniLangChainTool(
                tool=tool,
                gate=gate,
                decision_type=tool_policy.get("decision_type", default_decision_type),
                blast_radius=tool_policy.get("blast_radius", default_blast_radius),
                proposed_by=proposed_by,
            )
        )
        logger.info("Patched LangChain tool | name=%s (dsal=auto)", tool.name)

    return governed
