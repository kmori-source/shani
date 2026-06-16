"""
Scenario 6: LangGraph + Shani HITL

Simulates a security response LangGraph agent with Shani governance.

Graph topology:
    detect → [SHANI APPROVAL] → isolate → [SHANI APPROVAL] → rotate → report

Three Shani integration points demonstrated:
    1. Tool-level:  each tool is wrapped (zero graph changes)
    2. Node-level:  isolate and rotate nodes require pre-approval
    3. Mid-execution: watchdog monitors running nodes

Run modes:
    SHANI_HITL_AUTO=approve python scenario.py   (automated, CI-safe)
    python scenario.py                            (interactive CLI)
"""

import sys as _sys, os as _os

_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "../.."))
try:
    import pydantic
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
    _sys.modules["pydantic"] = _shim
import warnings as _w

_w.filterwarnings("ignore")

import os
import sys
import time
import threading
import uuid
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from datetime import datetime, timedelta, timezone

from shani import (
    ShaniEvaluator,
    StaticAuthorityProvider,
    DecisionType,
    BlastRadius,
)
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl.approval.gate import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel, CLIApprovalChannel
from shani.hitl.mid_execution.monitor import MidExecutionMonitor, ExecutionAborted
from shani.adapters.langgraph.adapter import governed_node, shani_tools, ShaniLangGraph
from shani.schemas.decision import DecisionScope, EvidenceItem, DecisionProposal

AUTO_MODE = os.environ.get("SHANI_HITL_AUTO", "").lower()

# ─────────────────────────────────────────────────────────
# Simulated LangGraph state and nodes
# (real LangGraph would use TypedDict + StateGraph + add_node)
# ─────────────────────────────────────────────────────────


def detect_node(state: dict) -> dict:
    """Detect malware — no approval needed (D-SAL 1)."""
    print("    [detect] Scanning host for indicators...")
    time.sleep(0.2)
    return {
        **state,
        "threat_detected": True,
        "target": "host:prod-db-12",
        "evidence": [
            {"source": "EDR-22314", "content": "Lateral movement detected", "confidence": 0.93},
        ],
    }


def isolate_node(state: dict) -> dict:
    """Isolate host — D-SAL 2, HITL required."""
    ado = state.get("shani_ado")
    print(
        f"    [isolate] Isolating {state.get('target')} — authorized by {ado.authority if ado else '?'}"
    )
    time.sleep(0.3)
    return {**state, "host_isolated": True}


def rotate_node(state: dict) -> dict:
    """Rotate credentials — D-SAL 2, HITL required."""
    ado = state.get("shani_ado")
    print(
        f"    [rotate] Rotating credentials — parent={ado.parent_decision_id[:8] if ado and ado.parent_decision_id else 'root'}"
    )
    time.sleep(0.3)
    return {**state, "credentials_rotated": True}


def report_node(state: dict) -> dict:
    """Write incident report — no approval needed."""
    print(f"    [report] Incident report generated")
    return {**state, "report_written": True}


# ─────────────────────────────────────────────────────────
# Audit log — write-on-append so partial runs are preserved
# ─────────────────────────────────────────────────────────


class AuditLog:
    """Append-and-flush audit log. Every append writes to disk immediately
    so the file is valid JSON even if the process exits mid-run."""

    def __init__(self, path: str = "audit_langgraph.json"):
        self.path = Path(path)
        self._data = {
            "session": str(uuid.uuid4()),
            "scenario": "LangGraph HITL — security incident response",
            "started_at": datetime.now(tz=timezone.utc).isoformat(),
            "actions": [],
        }
        self._flush()  # create empty file at start

    def _flush(self):
        self.path.write_text(json.dumps(self._data, indent=2))

    def append(self, entry: dict):
        entry.setdefault("timestamp", datetime.now(tz=timezone.utc).isoformat())
        self._data["actions"].append(entry)
        self._flush()

    def finalize(self, status: str = "completed"):
        self._data["finished_at"] = datetime.now(tz=timezone.utc).isoformat()
        self._data["final_status"] = status
        self._flush()
        print(f"\n  audit written → {self.path}  ({len(self._data['actions'])} actions)")

    # ── helpers ──────────────────────────────────────────

    def record_ado(self, step: str, state: dict):
        """Record an AUTHORIZED or DENIED outcome from a governed node."""
        if state.get("shani_denied"):
            self.append(
                {
                    "step": step,
                    "status": "DENIED",
                    "reason": str(state["shani_denied"]),
                }
            )
        elif state.get("shani_ado"):
            ado = state["shani_ado"]
            self.append(
                {
                    "step": step,
                    "status": "AUTHORIZED",
                    "decision_id": str(ado.decision_id),
                    "authority": ado.authority,
                    "dsal": ado.authorized_dsal,
                    "proposal_hash": ado.proposal_hash,
                    "signature": ado.signature,
                    "issued_at": ado.issued_at.isoformat(),
                    "expires_at": ado.expires_at.isoformat(),
                }
            )

    def record_mid_execution(
        self, event: str, session_id: str, authority: str = None, detail: str = None
    ):
        """Record a mid-execution event (pause / resume / abort / complete)."""
        entry = {"step": "mid_execution", "event": event, "session_id": session_id}
        if authority:
            entry["authority"] = authority
        if detail:
            entry["detail"] = detail
        self.append(entry)


# ─────────────────────────────────────────────────────────
# Infrastructure
# ─────────────────────────────────────────────────────────


def build_gate(channel) -> HITLGate:
    agents = {
        "soc-agent/v1": AgentIdentity(
            agent_id="soc-agent/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                ["remediation", "configuration_change", "network_action"]
            ),
        ),
    }
    policy = DecisionPolicyProvider(agent_registry=agents)
    evaluator = ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=policy,
    )
    return HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=2,
        timeout_minutes=5,
    )


def build_callback_gate_with_auto(action: str):
    """Build a gate whose channel auto-approves or auto-denies."""
    channel = CallbackApprovalChannel()
    gate = build_gate(channel)

    def auto_respond(req):
        time.sleep(0.15)
        if action == "approve":
            channel.approve(req.request_id, "auto-operator", "automated test")
        else:
            channel.deny(req.request_id, "auto-operator", "automated denial")

    channel._on_new = auto_respond
    return gate


# ─────────────────────────────────────────────────────────
# Demo A: Pattern 1 — Tool-level governance
# ─────────────────────────────────────────────────────────


def demo_tool_level(gate: HITLGate):
    print("\n" + "─" * 58)
    print("Pattern 1: Tool-level governance (zero graph changes)")
    print("─" * 58)

    # Simulated LangChain tools
    class FakeTool:
        def __init__(self, name, desc):
            self.name = name
            self.description = desc

        def run(self, inp):
            return f"{self.name} executed: {inp}"

    raw_tools = [
        FakeTool("network_block", "Block network access for a host"),
        FakeTool("cred_rotate", "Rotate service credentials"),
    ]

    governed = shani_tools(
        tools=raw_tools,
        gate=gate,
        proposed_by="soc-agent/v1",
        policy={
            "network_block": dict(blast_radius=BlastRadius.SIGNIFICANT),
            "cred_rotate": dict(blast_radius=BlastRadius.LIMITED),
        },
    )

    print(f"  Wrapped {len(raw_tools)} tools → {len(governed)} governed tools")
    for t in governed:
        print(f"    • {t.name}: {t.description}")


# ─────────────────────────────────────────────────────────
# Demo B: Pattern 2 — Node-level governance
# ─────────────────────────────────────────────────────────


def demo_node_level(gate: HITLGate, audit: AuditLog):
    print("\n" + "─" * 58)
    print("Pattern 2: Node-level governance with mid-execution monitor")
    print("─" * 58)

    mid_monitor = MidExecutionMonitor(
        silence_threshold_seconds=30.0,
        on_silence=lambda s: print(f"  ⚠️  Silent agent: {s.agent_id} ({s.silence_seconds():.0f}s)"),
    )
    mid_monitor.start_watchdog()

    # Wrap the nodes that need HITL
    governed_isolate = governed_node(
        fn=isolate_node,
        gate=gate,
        decision_type=DecisionType.NETWORK_ACTION,
        blast_radius=BlastRadius.SIGNIFICANT,
        proposed_by="soc-agent/v1",
        target_extractor=lambda s: s.get("target", "unknown"),
        evidence_extractor=lambda s: [
            EvidenceItem(source=e["source"], content=e["content"], confidence=e["confidence"])
            for e in s.get("evidence", [])
        ],
        mid_monitor=mid_monitor,
    )

    governed_rotate = governed_node(
        fn=rotate_node,
        gate=gate,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        blast_radius=BlastRadius.LIMITED,
        proposed_by="soc-agent/v1",
        target_extractor=lambda s: f"cred:{s.get('target', 'unknown').split(':')[-1]}",
        mid_monitor=mid_monitor,
    )

    # Simulate graph execution: detect → isolate → rotate → report
    print("\n  Executing: detect → [HITL] isolate → [HITL] rotate → report")
    state = {}

    print("\n  Step 1: detect (no approval needed)")
    state = detect_node(state)
    audit.append(
        {
            "step": "detect",
            "status": "COMPLETED",
            "threat_detected": state["threat_detected"],
            "target": state["target"],
        }
    )
    print(f"    → threat_detected={state['threat_detected']} target={state['target']}")

    print("\n  Step 2: isolate (HITL required)")
    state = governed_isolate(state)
    audit.record_ado("isolate", state)  # written to disk immediately
    if state.get("shani_denied"):
        print(f"    ✗ DENIED: {state['shani_denied']}")
        mid_monitor.stop_watchdog()
        return  # audit already on disk
    print(
        f"    → host_isolated={state.get('host_isolated')} | ADO={state['shani_ado'].decision_id[:8]}"
    )

    print("\n  Step 3: rotate (HITL required, lineage from isolate)")
    state_with_parent = {
        **state,
        "__parent_decision_id__": state["shani_ado"].decision_id,
    }
    state = governed_rotate(state_with_parent)
    audit.record_ado("rotate", state)  # written to disk immediately
    if state.get("shani_denied"):
        print(f"    ✗ DENIED: {state['shani_denied']}")
        mid_monitor.stop_watchdog()
        return  # audit already on disk
    print(f"    → credentials_rotated={state.get('credentials_rotated')}")

    print("\n  Step 4: report (no approval needed)")
    state = report_node(state)
    audit.append(
        {"step": "report", "status": "COMPLETED", "report_written": state.get("report_written")}
    )
    print(f"    → report_written={state.get('report_written')}")

    print("\n  Active monitoring sessions:", len(mid_monitor.get_active_sessions()))
    mid_monitor.stop_watchdog()


# ─────────────────────────────────────────────────────────
# Demo C: Mid-execution intervention (pause/resume/abort)
# ─────────────────────────────────────────────────────────


def demo_mid_execution_intervention(gate: HITLGate, audit: AuditLog):
    print("\n" + "─" * 58)
    print("Pattern 3: Mid-execution pause → resume")
    print("─" * 58)

    mid_monitor = MidExecutionMonitor()

    # Build a minimal ADO-like object for the session
    class FakeADO:
        decision_id = str(uuid.uuid4())

        class intent_binding:
            target = "host:prod-db-12"

    session_id = mid_monitor.register(FakeADO(), agent_id="soc-agent/v1")
    print(f"  Session registered: {session_id}")
    audit.record_mid_execution(
        "session_started", session_id, detail="soc-agent/v1 → host:prod-db-12"
    )

    results = []

    def long_running_task():
        for i in range(6):
            mid_monitor.heartbeat(session_id, f"step {i + 1}/6")
            try:
                mid_monitor.checkpoint(session_id)  # pauses here if PAUSE active
            except ExecutionAborted as e:
                results.append(f"ABORTED at step {i + 1}: {e}")
                audit.record_mid_execution("aborted", session_id, detail=f"step {i + 1}/6: {e}")
                return
            time.sleep(0.15)
            results.append(f"step {i + 1} done")
        mid_monitor.complete(session_id, "all steps completed")
        audit.record_mid_execution("completed", session_id, detail="all 6 steps done")
        results.append("COMPLETED")

    task_thread = threading.Thread(target=long_running_task)
    task_thread.start()

    # Human pauses the task after step 2
    time.sleep(0.35)
    mid_monitor.pause(session_id, authority="alice@example.com", reason="reviewing step 2 output")
    audit.record_mid_execution(
        "paused", session_id, authority="alice@example.com", detail="reviewing step 2 output"
    )
    print("  [Human] PAUSED execution at step 2")

    # Human reviews for a moment, then resumes
    time.sleep(0.5)
    mid_monitor.resume(session_id, authority="alice@example.com")
    audit.record_mid_execution("resumed", session_id, authority="alice@example.com")
    print("  [Human] RESUMED execution")

    task_thread.join(timeout=5)
    print("  Results:", results)


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────


def main():
    print("=" * 58)
    print("SCENARIO 6: LangGraph + Shani HITL Integration")
    print("=" * 58)

    audit = AuditLog("audit_langgraph.json")  # creates file immediately

    if AUTO_MODE in ("approve", ""):
        print("\n[AUTO MODE — approve]\n" if AUTO_MODE else "\n[INTERACTIVE — approve all]\n")
        gate = build_callback_gate_with_auto("approve")

        demo_tool_level(gate)
        demo_node_level(gate, audit)
        demo_mid_execution_intervention(gate, audit)

    elif AUTO_MODE == "deny":
        gate = build_callback_gate_with_auto("deny")
        print("\n[AUTO MODE — deny all]\n")
        demo_node_level(gate, audit)

    else:
        channel = CLIApprovalChannel(operator_name="soc-operator")
        gate = build_gate(channel)
        demo_tool_level(gate)
        demo_node_level(gate, audit)
        demo_mid_execution_intervention(gate, audit)

    audit.finalize("completed")
    print("\n✓ Complete.")
    print("\n  To wire into a real LangGraph agent:")
    print("  1. Replace FakeTool with your actual tools")
    print("  2. Replace detect/isolate/rotate_node with your graph nodes")
    print("  3. Use StateGraph + add_node as normal")
    print("  4. Shani is the only addition — no agent logic changes")


if __name__ == "__main__":
    main()
