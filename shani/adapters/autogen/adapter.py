"""
Shani AutoGen / AG2 Adapter.

Wraps AutoGen function tool registrations with Shani governance.
The agent and its LLM configuration are not modified.

Usage:

    # BEFORE — standard AutoGen tool registration
    @user_proxy.register_for_execution()
    @assistant.register_for_llm(description="Restart a service")
    def restart_service(service: Annotated[str, "service name"]) -> str:
        ...

    # AFTER — Shani-governed, agent code unchanged
    governed = shani_autogen_tool(
        fn=restart_service,
        gate=hitl_gate,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        blast_radius=BlastRadius.SIGNIFICANT,
        proposed_by="autogen-assistant/v1",
        target_extractor=lambda kw: f"service:{kw['service']}",
    )

    @user_proxy.register_for_execution()
    @assistant.register_for_llm(description="Restart a service")
    def restart_service(service: Annotated[str, "service name"]) -> str:
        return governed(service=service)

Or use patch_autogen_agent to govern all tools at once:

    patch_autogen_agent(
        agent=user_proxy,
        gate=hitl_gate,
        proposed_by="autogen-agent/v1",
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
from ...adapters.generic.wrapper import ShaniToolWrapper, GovernanceGate

logger = logging.getLogger("shani.adapter.autogen")


def shani_autogen_tool(
    fn: Callable,
    gate: GovernanceGate,
    decision_type: DecisionType,
    blast_radius: BlastRadius,
    proposed_by: str,
    target_extractor: Callable[[dict], str] | str = "autogen-tool",
    **kwargs,
) -> ShaniToolWrapper:
    """
    Wrap an AutoGen tool function with Shani governance.

    Returns a ShaniToolWrapper that behaves identically to the original function
    from AutoGen's perspective, but routes every call through Shani.
    """
    return ShaniToolWrapper(
        fn=fn,
        gate=gate,
        decision_type=decision_type,
        blast_radius=blast_radius,
        proposed_by=proposed_by,
        target_extractor=target_extractor,
        **kwargs,
    )


def patch_autogen_agent(
    agent: Any,  # autogen.ConversableAgent — not imported to avoid hard dependency
    gate: GovernanceGate,
    proposed_by: str,
    policy: dict[str, dict] | None = None,
    default_dsal: int = 1,
    default_blast_radius: BlastRadius = BlastRadius.LIMITED,
    default_decision_type: DecisionType = DecisionType.REMEDIATION,
) -> None:
    """
    Monkey-patch an AutoGen agent's function map with Shani-governed versions.

    Modifies agent._function_map in-place.
    The agent's LLM schema, description, and conversation flow are unchanged.

    This is the zero-change integration path for AutoGen.
    """
    fn_map = getattr(agent, "_function_map", {})
    if not fn_map:
        logger.warning("Agent has no _function_map. Nothing to patch.")
        return

    policy = policy or {}
    patched = {}

    for fn_name, fn in fn_map.items():
        fn_policy = policy.get(fn_name, {})
        patched[fn_name] = ShaniToolWrapper(
            fn=fn,
            gate=gate,
            decision_type=fn_policy.get("decision_type", default_decision_type),
            blast_radius=fn_policy.get("blast_radius", default_blast_radius),
            proposed_by=proposed_by,
            target_extractor=fn_policy.get("target_extractor", f"autogen:{fn_name}"),
        )
        logger.info("Patched AutoGen function | name=%s dsal=%s", fn_name, "(auto)")

    agent._function_map = patched
    logger.info("AutoGen agent patched | %d functions governed", len(patched))
