"""
LangGraph + Shani — ExecutionBoundary Demo

Fixes the following problem:
    Before: call_external_api(url)  ← could be called directly without ADO
    After:  cap = boundary.issue_capability(ado)
            cap.http_get(url)        ← cap cannot be obtained without ADO

Graph structure:
    START → search_node → summarize_node → END
                ↓                ↓
         Shani D-SAL 1     Shani D-SAL 2
         → Capability      → Capability
         → cap.http_get()  → cap.http_post()

Usage:
    python demo.py                          # mock LLM
    OLLAMA_MODEL=llama3.2 python demo.py    # Ollama
    OPENAI_API_KEY=sk-... python demo.py    # OpenAI
"""

from __future__ import annotations

import os, sys, time, threading
from typing import Annotated, TypedDict

# ── Shani bootstrap ───────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import pydantic  # noqa
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

warnings.filterwarnings("ignore", category=UserWarning, module="shani")

from datetime import datetime, timedelta, timezone

from langchain_core.messages import HumanMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem
from shani.boundary.capability import ExecutionBoundary, CapabilityError


# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    query: str
    api_result: str
    summary: str
    shani_log: list[str]


# ─────────────────────────────────────────────────────────────────────────────
# Shani + Boundary setup
# ─────────────────────────────────────────────────────────────────────────────


def build_gate() -> tuple[HITLGate, CallbackApprovalChannel]:
    channel = CallbackApprovalChannel()
    agents = {
        "langgraph-agent/v1": AgentIdentity(
            agent_id="langgraph-agent/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(
                ["data_access", "configuration_change", "remediation"]
            ),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    gate = HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=2,
        timeout_minutes=2,
    )
    return gate, channel


def request_capability(
    gate: HITLGate,
    boundary: ExecutionBoundary,
    decision_type: DecisionType,
    target: str,
    description: str,
    dsal: int,
    evidence_text: str = "",
):
    """
    Request approval from Shani and obtain a Capability.
    If no ADO is issued, no Capability can be obtained.
    """
    from shani import DeniedDecision

    evidence = []
    if evidence_text:
        evidence = [
            EvidenceItem(
                source="agent-observation",
                content=evidence_text,
                confidence=0.85,
            )
        ]

    proposal = DecisionProposal(
        decision_type=decision_type,
        proposed_by="langgraph-agent/v1",
        description=description,
        target=target,
        scope=DecisionScope(asset_ids=[target]),
        evidence=evidence,
        confidence=0.85,
        reversibility=True,
        blast_radius=BlastRadius.LIMITED,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
    )

    ado = gate.evaluate(proposal)

    if isinstance(ado, DeniedDecision):
        return None, ado.reason

    # ADO → Capability (re-verify + consume nonce)
    cap = boundary.issue_capability(ado, proposal)
    return cap, None


# ─────────────────────────────────────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────────────────────────────────────


def get_llm():
    ollama_model = os.environ.get("OLLAMA_MODEL")
    if ollama_model:
        try:
            from langchain_ollama import ChatOllama

            print(f"  [LLM] Ollama ({ollama_model})")
            return ChatOllama(model=ollama_model, temperature=0)
        except ImportError:
            print("  [LLM] pip install langchain-ollama is required")

    if os.environ.get("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI

        print("  [LLM] OpenAI GPT-4o")
        return ChatOpenAI(model="gpt-4o", temperature=0)

    print("  [LLM] Mock (set OLLAMA_MODEL=llama3.2 or OPENAI_API_KEY for a real LLM)")
    return MockLLM()


class MockLLM:
    def invoke(self, messages):
        last = messages[-1].content if messages else ""
        if "summarize" in last.lower() or "summary" in last.lower():
            return AIMessage(
                content=("3 items found. Latency 38ms, no errors. Operating normally.")
            )
        return AIMessage(content=f"Processing query: {last[:40]}")


# ─────────────────────────────────────────────────────────────────────────────
# Nodes
# ─────────────────────────────────────────────────────────────────────────────


def search_node(state: AgentState, gate: HITLGate, boundary: ExecutionBoundary) -> AgentState:
    """GET node. Can only be called via cap.http_get()."""
    query = state["query"]
    target_url = f"https://api.example.com/search?q={query}"
    log = list(state.get("shani_log", []))

    print(f"\n  [search] Approval request (D-SAL 1) → {target_url[:55]}")

    cap, err = request_capability(
        gate=gate,
        boundary=boundary,
        decision_type=DecisionType.DATA_ACCESS,
        target=target_url,
        description=f"External API search for: {query}.",
        dsal=1,
    )

    if err:
        log.append(f"❌ GET denied: {err}")
        return {**state, "api_result": f"denied: {err}", "shani_log": log}

    print(f"  [search] ✓ Capability issued → {cap}")
    result = cap.http_get(target_url)
    data = str(result["data"])
    print(f"  [search] ✓ Complete: {data[:60]}")
    log.append(f"✅ GET (D-SAL 1, auto) | {cap}")

    return {
        **state,
        "api_result": data,
        "messages": [AIMessage(content=f"Fetched: {data}")],
        "shani_log": log,
    }


def summarize_node(
    state: AgentState,
    gate: HITLGate,
    boundary: ExecutionBoundary,
    llm,
) -> AgentState:
    """LLM summarize → POST node. Can only be called via cap.http_post()."""
    api_result = state.get("api_result", "")
    target_url = "https://api.example.com/reports"
    log = list(state.get("shani_log", []))

    summary = llm.invoke(
        [HumanMessage(content=f"Summarize the following data: {api_result}")]
    ).content
    print(f"\n  [summarize] LLM: {summary[:60]}")
    print(f"  [summarize] Approval request (D-SAL 2, HITL) → {target_url}")

    cap, err = request_capability(
        gate=gate,
        boundary=boundary,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        target=target_url,
        description="POST summary report to external API.",
        dsal=2,
        evidence_text=f"LLM summary: {summary[:80]}",
    )

    if err:
        log.append(f"❌ POST denied: {err}")
        return {**state, "summary": f"denied: {err}", "shani_log": log}

    print(f"  [summarize] ✓ Capability issued → {cap}")
    result = cap.http_post(target_url, {"summary": summary})
    print(f"  [summarize] ✓ Complete: id={result['id']}")
    log.append(f"✅ POST (D-SAL 2, HITL) | {cap}")

    return {
        **state,
        "summary": summary,
        "messages": [AIMessage(content=f"Saved: {result['id']}")],
        "shani_log": log,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Boundary enforcement tests
# ─────────────────────────────────────────────────────────────────────────────


def test_bypass_attempts(boundary: ExecutionBoundary):
    print("\n  ── Boundary bypass tests ───────────────────────────")

    # 1. Attempt direct Capability() construction
    print("  1. Direct Capability() construction:")
    try:
        from shani.boundary.capability import Capability

        Capability(object(), None, {"http_get"}, "https://")
        print("     ✗ construction succeeded (design bug)")
    except Exception as e:
        print(f"     ✓ blocked: {type(e).__name__}")

    # 2. Attempt issue_capability with fake ADO
    print("  2. Fake ADO with issue_capability():")
    try:

        class FakeADO:
            decision_id = "fake-000"
            signature = "invalid_signature"
            proposal_hash = "bad_hash"
            nonce = "00" * 32
            issued_at = datetime.now(tz=timezone.utc)
            expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=5)

            def is_expired(self):
                return False

            class exec_context:
                class decision_type:
                    value = "data_access"

                class intent_binding:
                    target = "https://api.example.com"

        boundary.issue_capability(FakeADO())
        print("     ✗ Capability was issued (design bug)")
    except (CapabilityError, Exception) as e:
        print(f"     ✓ blocked: {type(e).__name__}")

    print("  ────────────────────────────────────────────────────")


# ─────────────────────────────────────────────────────────────────────────────
# HITL auto-response
# ─────────────────────────────────────────────────────────────────────────────


def start_auto_approver(channel: CallbackApprovalChannel, action: str = "approve"):
    def loop():
        seen = set()
        for _ in range(120):
            time.sleep(0.3)
            for req in channel.get_pending():
                if req.request_id in seen:
                    continue
                seen.add(req.request_id)
                print(f"\n  ┌─ HITL ──────────────────────────────────────")
                print(f"  │  {req.decision_type}  →  {req.target[:45]}")
                print(f"  │  authority: {req.required_authority}")
                print(f"  └─────────────────────────────────────────────")
                time.sleep(0.4)
                if action == "approve":
                    channel.approve(req.request_id, "operator@example.com", "confirmed")
                    print("  → ✓ Approved")
                else:
                    channel.deny(req.request_id, "operator@example.com", "rejected")
                    print("  → ✗ Denied")

    threading.Thread(target=loop, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


def run(query: str = "latest metrics", hitl_action: str = "approve"):
    print("\n" + "=" * 57)
    print("  LangGraph + Shani ExecutionBoundary Demo")
    print("=" * 57)

    gate, channel = build_gate()
    boundary = ExecutionBoundary(gate)
    llm = get_llm()

    test_bypass_attempts(boundary)
    start_auto_approver(channel, hitl_action)

    builder = StateGraph(AgentState)
    builder.add_node("search", lambda s: search_node(s, gate, boundary))
    builder.add_node("summarize", lambda s: summarize_node(s, gate, boundary, llm))
    builder.add_edge(START, "search")
    builder.add_edge("search", "summarize")
    builder.add_edge("summarize", END)
    graph = builder.compile()

    print(f"\n  Query: {query} / HITL: {hitl_action}")
    print("  Running graph...")

    final = graph.invoke(
        {
            "messages": [HumanMessage(content=query)],
            "query": query,
            "api_result": "",
            "summary": "",
            "shani_log": [],
        }
    )

    print("\n" + "─" * 57)
    print("  [Results]")
    print(f"  API result: {final['api_result'][:80]}")
    print(f"  Summary:   {final['summary'][:100]}")
    print(f"\n  Shani log:")
    for entry in final.get("shani_log", []):
        print(f"    {entry}")
    print()
    print("  [Design notes]")
    print("    call_external_api(url) does not exist")
    print("    cap = boundary.issue_capability(ado) is the only way to execute operations")
    print("    no ADO → CapabilityError → execution blocked")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--query", default="system metrics for prod-cluster")
    p.add_argument("--deny", action="store_true")
    args = p.parse_args()
    run(query=args.query, hitl_action="deny" if args.deny else "approve")
