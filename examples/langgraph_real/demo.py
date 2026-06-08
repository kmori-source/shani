"""
examples/langgraph_real/demo.py

Real LangGraph + Shani integration demo.

A security incident response agent built with actual LangGraph StateGraph.
Shani governs the high-risk nodes (isolate, rotate) before execution.

Run:
    SHANI_HITL_AUTO=approve python examples/langgraph_real/demo.py

Requirements:
    pip install "shani[langchain]" langgraph langchain-anthropic
"""
import os
import sys
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict, Annotated
import operator

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

# ── Shani imports ──
from shani import ShaniEvaluator, StaticAuthorityProvider, DecisionType, BlastRadius
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.langgraph import governed_node
from shani.schemas.decision import EvidenceItem

# ── LangGraph imports ──
from langgraph.graph import StateGraph, END
from langchain_anthropic import ChatAnthropic
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, AIMessage

HITL_AUTO = os.environ.get("SHANI_HITL_AUTO", "approve").lower()

# ─────────────────────────────────────────────────────────
# State definition
# ─────────────────────────────────────────────────────────

class IncidentState(TypedDict):
    messages: Annotated[list, operator.add]
    threat_detected: bool
    target: str
    evidence: list[dict]
    host_isolated: bool
    credentials_rotated: bool
    report: str
    shani_ado: object | None
    shani_denied: str | None


# ─────────────────────────────────────────────────────────
# Shani gate setup
# ─────────────────────────────────────────────────────────

def build_gate() -> HITLGate:
    agents = {
        "soc-agent/v1": AgentIdentity(
            agent_id="soc-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset([
                "remediation", "configuration_change", "network_action"
            ]),
        )
    }
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )
    channel = CallbackApprovalChannel()

    # Auto-approve or auto-deny for demo
    import time, threading
    def auto_respond():
        seen = set()
        for _ in range(120):
            time.sleep(0.3)
            for req in channel.get_pending():
                if req.request_id in seen:
                    continue
                seen.add(req.request_id)
                print(f"\n  [HITL] type={req.decision_type} target={req.target}")
                time.sleep(0.2)
                if HITL_AUTO == "deny":
                    channel.deny(req.request_id, "operator@example.com", "auto-deny")
                    print("  → ✗ Denied")
                else:
                    channel.approve(req.request_id, "operator@example.com", "auto-approve")
                    print("  → ✓ Approved")

    threading.Thread(target=auto_respond, daemon=True).start()

    return HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=2,
        timeout_minutes=5,
    )


# ─────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────

class AuditLog:
    def __init__(self, path: str = "audit_langgraph_real.json"):
        self.path = Path(path)
        self._data = {
            "session": str(uuid.uuid4()),
            "scenario": "Real LangGraph + Shani — security incident response",
            "started_at": datetime.now(tz=timezone.utc).isoformat(),
            "actions": [],
        }
        self._flush()

    def _flush(self):
        self.path.write_text(json.dumps(self._data, indent=2))

    def append(self, entry: dict):
        entry.setdefault("timestamp", datetime.now(tz=timezone.utc).isoformat())
        self._data["actions"].append(entry)
        self._flush()

    def record_ado(self, step: str, state: dict):
        if state.get("shani_denied"):
            self.append({"step": step, "status": "DENIED", "reason": str(state["shani_denied"])})
        elif state.get("shani_ado"):
            ado = state["shani_ado"]
            self.append({
                "step": step, "status": "AUTHORIZED",
                "decision_id": str(ado.decision_id),
                "authority": ado.authority,
                "dsal": ado.authorized_dsal,
                "proposal_hash": ado.proposal_hash,
                "signature": ado.signature,
                "issued_at": ado.issued_at.isoformat(),
            })

    def finalize(self, status: str = "completed"):
        self._data["finished_at"] = datetime.now(tz=timezone.utc).isoformat()
        self._data["final_status"] = status
        self._flush()
        print(f"\n  audit written → {self.path}  ({len(self._data['actions'])} actions)")


# ─────────────────────────────────────────────────────────
# LangGraph nodes
# ─────────────────────────────────────────────────────────

llm = ChatOllama(model="qwen2.5:7b", base_url="http://localhost:11434")


def detect_node(state: IncidentState) -> dict:
    """Detect threat — LLM analyzes the situation."""
    print("\n  Step 1: detect (LLM analyzing...)")
    response = llm.invoke([
        HumanMessage(content=(
            "You are a security analyst. A monitoring alert was triggered for host:prod-db-12. "
            "EDR reports lateral movement detected with confidence 0.93. "
            "Respond with a brief threat assessment in one sentence."
        ))
    ])
    print(f"    LLM: {response.content[:80]}...")
    return {
        "messages": [response],
        "threat_detected": True,
        "target": "host:prod-db-12",
        "evidence": [
            {"source": "EDR-22314", "content": "Lateral movement detected", "confidence": 0.93},
            {"source": "SIEM-9901", "content": "Anomalous outbound traffic on prod-db-12", "confidence": 0.88},
        ],
    }

def isolate_node(state: IncidentState) -> dict:
    """Isolate host — governed by Shani."""
    ado = state.get("shani_ado")
    audit.record_ado("isolate", state)
    print(f"    [isolate] Isolating {state['target']} — authorized by {ado.authority if ado else '?'}")
    return {"host_isolated": True}


def rotate_node(state: IncidentState) -> dict:
    """Rotate credentials — governed by Shani."""
    ado = state.get("shani_ado")
    audit.record_ado("rotate", state)
    print(f"    [rotate] Rotating credentials — dsal={ado.authorized_dsal if ado else '?'}")
    return {"credentials_rotated": True}


def report_node(state: IncidentState) -> dict:
    """Generate incident report — LLM summarizes."""
    print("\n  Step 4: report (LLM generating...)")
    isolated = state.get("host_isolated", False)
    rotated = state.get("credentials_rotated", False)
    response = llm.invoke([
        HumanMessage(content=(
            f"Generate a brief incident report. "
            f"Target: {state['target']}. "
            f"Host isolated: {isolated}. Credentials rotated: {rotated}. "
            f"Keep it to 2 sentences."
        ))
    ])
    print(f"    LLM: {response.content[:80]}...")
    return {"messages": [response], "report": response.content}


def should_continue(state: IncidentState) -> str:
    """Route based on Shani's decision."""
    if state.get("shani_denied"):
        return "report"  # Skip to report if denied
    return "continue"


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

audit = AuditLog()

def main():
    print("=" * 58)
    print(f"  Real LangGraph + Shani Integration")
    print(f"  SHANI_HITL_AUTO={HITL_AUTO}")
    print("=" * 58)

    gate = build_gate()

    # Wrap high-risk nodes with Shani governance
    governed_isolate = governed_node(
        fn=isolate_node,
        gate=gate,
        decision_type=DecisionType.NETWORK_ACTION,
        blast_radius=BlastRadius.SIGNIFICANT,
        proposed_by="soc-agent/v1",
        target_extractor=lambda s: s.get("target", "unknown"),
        evidence_extractor=lambda s: [
            EvidenceItem(
                source=e["source"],
                content=e["content"],
                confidence=e["confidence"]
            )
            for e in s.get("evidence", [])
        ],
    )

    governed_rotate = governed_node(
        fn=rotate_node,
        gate=gate,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        blast_radius=BlastRadius.LIMITED,
        proposed_by="soc-agent/v1",
        target_extractor=lambda s: f"cred:{s.get('target', 'unknown').split(':')[-1]}",
        evidence_extractor=lambda s: [
            EvidenceItem(
                source=e["source"],
                content=e["content"],
                confidence=e["confidence"]
            )
            for e in s.get("evidence", [])
        ],
    )

    # Build the actual LangGraph StateGraph
    workflow = StateGraph(IncidentState)

    workflow.add_node("detect", detect_node)
    workflow.add_node("isolate", governed_isolate)
    workflow.add_node("rotate", governed_rotate)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("detect")

    workflow.add_edge("detect", "isolate")
    workflow.add_conditional_edges(
        "isolate",
        should_continue,
        {"continue": "rotate", "report": "report"},
    )
    workflow.add_conditional_edges(
        "rotate",
        should_continue,
        {"continue": "report", "report": "report"},
    )
    workflow.add_edge("report", END)

    graph = workflow.compile()

    # Run the graph
    print("\n  Graph: detect → [Shani] isolate → [Shani] rotate → report\n")

    initial_state: IncidentState = {
        "messages": [],
        "threat_detected": False,
        "target": "",
        "evidence": [],
        "host_isolated": False,
        "credentials_rotated": False,
        "report": "",
        "shani_ado": None,
        "shani_denied": None,
    }

    final_state = graph.invoke(initial_state)

    # Record audit
    audit.append({
        "step": "report",
        "status": "COMPLETED",
        "host_isolated": final_state.get("host_isolated"),
        "credentials_rotated": final_state.get("credentials_rotated"),
    })
    audit.finalize()

    print("\n✓ Complete.")
    print(f"  host_isolated={final_state.get('host_isolated')}")
    print(f"  credentials_rotated={final_state.get('credentials_rotated')}")


if __name__ == "__main__":
    main()
