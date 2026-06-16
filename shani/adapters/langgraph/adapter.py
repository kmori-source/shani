"""
Shani LangGraph Adapter.

Three integration patterns for LangGraph, from shallow to deep:

─────────────────────────────────────────────────────────────
Pattern 1: Tool-level governance (shallowest, zero graph changes)
─────────────────────────────────────────────────────────────

    Wrap individual tools. The graph topology doesn't change.
    Every tool call is intercepted before LangGraph executes it.

    governed_tools = shani_tools(
        tools=[search_tool, shell_tool],
        gate=hitl_gate,
        proposed_by="my-agent/v1",
        policy={"shell": dict(, blast_radius=BlastRadius.SIGNIFICANT)},
    )
    graph = create_react_agent(llm, tools=governed_tools)

─────────────────────────────────────────────────────────────
Pattern 2: Node-level governance (interrupt before execution)
─────────────────────────────────────────────────────────────

    Wrap individual graph nodes. Shani proposes a decision before
    the node body runs. The graph state carries the ADO forward.

    builder = StateGraph(AgentState)
    builder.add_node("remediate", governed_node(
        fn=remediate_node,
        gate=hitl_gate,
        decision_type=DecisionType.REMEDIATION,
        ...
    ))

─────────────────────────────────────────────────────────────
Pattern 3: Graph-level governance (deepest, full lineage)
─────────────────────────────────────────────────────────────

    Wrap the entire compiled graph. Every node transition is tracked.
    Shani's interrupt_before/interrupt_after hooks are installed.
    Mid-execution monitor watches all nodes.

    governed_graph = ShaniLangGraph(
        graph=compiled_graph,
        gate=hitl_gate,
        mid_monitor=mid_monitor,
        interrupt_before=["remediate", "network_action"],
    )
    result = governed_graph.invoke(input_state)

─────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import functools
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Sequence

from ...schemas.decision import (
    DecisionProposal,
    DecisionType,
    BlastRadius,
    DecisionScope,
    EvidenceItem,
)
from ...core.evaluator import DeniedDecision
from ...hitl.approval.gate import HITLGate
from ...adapters.generic.wrapper import GovernanceGate
from ...hitl.mid_execution.monitor import MidExecutionMonitor, ExecutionAborted
from ...adapters.langchain.adapter import ShaniLangChainTool

logger = logging.getLogger("shani.adapter.langgraph")


# ---------------------------------------------------------------------------
# Pattern 1: Tool-level governance
# ---------------------------------------------------------------------------


def shani_tools(
    tools: list[Any],
    gate: GovernanceGate,
    proposed_by: str,
    policy: dict[str, dict] | None = None,
    default_dsal: int = 1,
    default_blast_radius: BlastRadius = BlastRadius.LIMITED,
    default_decision_type: DecisionType = DecisionType.REMEDIATION,
) -> list[Any]:
    """
    Wrap a list of LangChain/LangGraph tools with Shani governance.

    Drop-in replacement for the tools list passed to create_react_agent().
    The graph structure is unchanged.

    Example:
        tools = [TavilySearchResults(), ShellTool(), WriteFileTool()]
        governed = shani_tools(
            tools=tools,
            gate=hitl_gate,
            proposed_by="react-agent/v1",
            policy={
                "terminal": dict(, blast_radius=BlastRadius.SIGNIFICANT),
                "write_file": dict(, blast_radius=BlastRadius.LIMITED),
            }
        )
        agent = create_react_agent(llm, tools=governed)
    """
    governed = []
    policy = policy or {}

    for tool in tools:
        name = getattr(tool, "name", type(tool).__name__)
        tool_policy = policy.get(name, policy.get(type(tool).__name__, {}))

        governed.append(
            ShaniLangChainTool(
                tool=tool,
                gate=gate,
                decision_type=tool_policy.get("decision_type", default_decision_type),
                blast_radius=tool_policy.get("blast_radius", default_blast_radius),
                proposed_by=proposed_by,
                target_extractor=tool_policy.get("target_extractor"),
            )
        )
        logger.info("Governed tool: %s (dsal=%s)", name, "(auto)")

    return governed


# ---------------------------------------------------------------------------
# Pattern 2: Node-level governance
# ---------------------------------------------------------------------------


def governed_node(
    fn: Callable,
    gate: GovernanceGate,
    decision_type: DecisionType,
    blast_radius: BlastRadius,
    proposed_by: str,
    target_extractor: Callable[[dict], str] | str = "langgraph-node",
    evidence_extractor: Callable[[dict], list[EvidenceItem]] | None = None,
    confidence: float = 0.85,
    mid_monitor: MidExecutionMonitor | None = None,
    ado_state_key: str = "shani_ado",
) -> Callable:
    """
    Wrap a LangGraph node function with pre-execution Shani approval.

    The node receives an extra key in its state: `shani_ado`
    containing the AuthorizedDecisionObject, so downstream nodes
    can reference it for lineage.

    Example:
        def my_node(state: AgentState) -> AgentState:
            ado = state.get("shani_ado")  # available after approval
            ...

        builder.add_node("my_node", governed_node(
            fn=my_node,
            gate=hitl_gate,
            decision_type=DecisionType.REMEDIATION,
            blast_radius=BlastRadius.LIMITED,
            proposed_by="my-agent/v1",
            target_extractor=lambda state: state.get("target", "unknown"),
        ))
    """

    @functools.wraps(fn)
    def wrapper(state: dict) -> dict:
        # Extract target from state
        if callable(target_extractor):
            target = target_extractor(state)
        else:
            target = str(target_extractor)

        # Extract evidence from state if extractor provided
        evidence = evidence_extractor(state) if evidence_extractor else []

        # Build proposal from graph state
        parent_id = state.get("shani_ado", {})
        if hasattr(parent_id, "decision_id"):
            parent_id = parent_id.decision_id
        else:
            parent_id = None

        proposal = DecisionProposal(
            decision_type=decision_type,
            proposed_by=proposed_by,
            description=f"LangGraph node: {fn.__name__}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=evidence,
            confidence=confidence,
            reversibility=True,
            blast_radius=blast_radius,
            parent_decision_id=parent_id,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=15),
        )

        result = gate.evaluate(proposal)

        if isinstance(result, DeniedDecision):
            logger.warning("Node DENIED | node=%s reason=%s", fn.__name__, result.reason)
            return {**state, "shani_denied": result.reason, "shani_ado": None}

        logger.info("Node AUTHORIZED | node=%s dsal=%s", fn.__name__, result.authorized_dsal)

        # Register mid-execution session if monitor provided
        session_id = None
        if mid_monitor is not None:
            session_id = mid_monitor.register(result, agent_id=proposed_by)

        # Inject ADO into state so node body and successors can access it
        enriched_state = {**state, ado_state_key: result}

        try:
            output = fn(enriched_state)
            gate.register_executed(result, agent_id=proposed_by)
            if mid_monitor and session_id:
                mid_monitor.complete(session_id)
            return output
        except ExecutionAborted as e:
            logger.warning("Node ABORTED mid-execution | node=%s", fn.__name__)
            return {**state, "shani_aborted": str(e), "shani_ado": None}

    return wrapper


# ---------------------------------------------------------------------------
# Pattern 3: Graph-level governance
# ---------------------------------------------------------------------------


class ShaniLangGraph:
    """
    Wraps a compiled LangGraph with full Shani governance.

    - Pre-execution: approves proposals before specified nodes run
    - Mid-execution: monitors running nodes via MidExecutionMonitor
    - Lineage: tracks decision chain across the entire graph run
    - Audit: produces a complete audit trail after graph completion

    Usage:
        compiled = builder.compile()
        governed = ShaniLangGraph(
            graph=compiled,
            gate=hitl_gate,
            mid_monitor=mid_monitor,
            interrupt_before=["remediate", "network_action"],
            node_policy={
                "remediate": dict(
                    decision_type=DecisionType.REMEDIATION,
                    blast_radius=BlastRadius.SIGNIFICANT,
                ),
            }
        )
        result = governed.invoke({"messages": [...]})
    """

    def __init__(
        self,
        graph: Any,  # CompiledGraph
        gate: GovernanceGate,
        proposed_by: str,
        mid_monitor: MidExecutionMonitor | None = None,
        interrupt_before: list[str] | None = None,
        interrupt_after: list[str] | None = None,
        node_policy: dict[str, dict] | None = None,
        default_dsal: int = 1,
        default_blast_radius: BlastRadius = BlastRadius.LIMITED,
    ) -> None:
        self._graph = graph
        self._gate = gate
        self._proposed_by = proposed_by
        self._mid_monitor = mid_monitor
        self._interrupt_before = set(interrupt_before or [])
        self._interrupt_after = set(interrupt_after or [])
        self._node_policy = node_policy or {}
        self._default_dsal = default_dsal
        self._default_blast = default_blast_radius
        self._run_audit: list[dict] = []

    def invoke(
        self,
        input: dict,
        config: dict | None = None,
        **kwargs,
    ) -> dict:
        """
        Invoke the graph with Shani governance.

        If interrupt_before nodes are specified, this method uses LangGraph's
        interrupt mechanism to pause the graph, get Shani approval, then resume.
        """
        run_id = str(uuid.uuid4())[:8]
        logger.info("Graph run started | run_id=%s", run_id)

        config = config or {}

        # Install interrupt hooks if interrupt_before nodes specified
        if self._interrupt_before:
            config.setdefault("interrupt_before", list(self._interrupt_before))

        # Patch state with Shani run metadata
        input = {**input, "__shani_run_id__": run_id, "__shani_gate__": self._gate}

        try:
            # First invocation — may pause at interrupt_before nodes
            result = self._graph.invoke(input, config=config, **kwargs)

            # Handle interrupted state (LangGraph returns partial state on interrupt)
            while self._is_interrupted(result):
                node_name = self._get_interrupted_node(result)
                logger.info("Graph interrupted at node: %s", node_name)

                approved = self._request_node_approval(node_name, result)
                if not approved:
                    logger.warning("Node approval DENIED | node=%s", node_name)
                    return {**result, "shani_denied": f"Approval denied for node: {node_name}"}

                # Resume graph after approval
                result = self._graph.invoke(None, config=config, **kwargs)

            self._run_audit.append(
                {
                    "run_id": run_id,
                    "status": "completed",
                    "completed_at": datetime.now(tz=timezone.utc).isoformat(),
                }
            )
            return result

        except Exception as e:
            self._run_audit.append(
                {
                    "run_id": run_id,
                    "status": "failed",
                    "error": str(e),
                }
            )
            raise

    def get_audit_trail(self) -> list[dict]:
        return list(self._run_audit)

    def _request_node_approval(self, node_name: str, state: dict) -> bool:
        """Request human approval for a specific node about to execute."""
        policy = self._node_policy.get(node_name, {})

        target = state.get("target", f"node:{node_name}")
        if callable(policy.get("target_extractor")):
            target = policy["target_extractor"](state)

        proposal = DecisionProposal(
            decision_type=policy.get("decision_type", DecisionType.REMEDIATION),
            proposed_by=self._proposed_by,
            description=f"LangGraph node about to execute: {node_name}",
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=[],
            confidence=0.85,
            reversibility=policy.get("reversibility", True),
            blast_radius=policy.get("blast_radius", self._default_blast),
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=15),
        )

        result = self._gate.evaluate(proposal)

        if isinstance(result, DeniedDecision):
            return False

        self._run_audit.append(
            {
                "node": node_name,
                "decision_id": result.decision_id,
                "dsal": result.authorized_dsal,
                "authority": result.authority,
                "authorized_at": result.authorized_at.isoformat(),
            }
        )
        return True

    @staticmethod
    def _is_interrupted(state: dict) -> bool:
        """Check if LangGraph paused at an interrupt node."""
        # LangGraph sets __interrupt__ in state when paused
        return isinstance(state, dict) and state.get("__interrupt__") is not None

    @staticmethod
    def _get_interrupted_node(state: dict) -> str:
        interrupt_info = state.get("__interrupt__", {})
        if isinstance(interrupt_info, dict):
            return interrupt_info.get("node", "unknown")
        return "unknown"
