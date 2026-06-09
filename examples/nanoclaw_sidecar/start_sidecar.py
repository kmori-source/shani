
# examples/nanoclaw_sidecar/start_sidecar.py
#
# Shani sidecar server for nanoclaw integration.
# Listens on 0.0.0.0:8765 so nanoclaw containers can reach it via 172.17.0.1:8765.
#
# Usage:
#   python examples/nanoclaw_sidecar/start_sidecar.py
#
# Environment variables:
#   SHANI_HITL_AUTO=approve  — auto-approve all HITL requests (for testing)
#   SHANI_HITL_AUTO=deny     — auto-deny all HITL requests (for testing)
#   SHANI_HOST               — bind address (default: 0.0.0.0)
#   SHANI_PORT               — port (default: 8765)

import os
import threading
import time

from shani import ShaniEvaluator, StaticAuthorityProvider
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.hitl import HITLGate
from shani.hitl.channel.channels import CallbackApprovalChannel
from shani.adapters.nanoclaw.sidecar import ShaniSidecarServer

HITL_AUTO = os.environ.get("SHANI_HITL_AUTO", "").lower()

agents = {
    "nanoclaw-agent/v1": AgentIdentity(
        agent_id="nanoclaw-agent/v1",
        granted_dsal=3,
        allowed_decision_types=frozenset([
            "remediation", "configuration_change", "data_access",
            "network_action",
        ]),
    )
}

channel = CallbackApprovalChannel(
    on_new_request=lambda req: print(f"[HITL] {req.to_display_dict()}")
)

gate = HITLGate(
    evaluator=ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    ),
    channel=channel,
    approval_required_at_dsal=2,
    timeout_minutes=10,
)


def auto_respond():
    """Auto-approve or auto-deny HITL requests for testing."""
    seen = set()
    while True:
        time.sleep(0.5)
        try:
            for req in channel.get_pending():
                if req.request_id in seen:
                    continue
                seen.add(req.request_id)
                time.sleep(0.5)
                if HITL_AUTO == "deny":
                    channel.deny(req.request_id, "operator@example.com", "auto-deny")
                    print(f"[HITL] ✗ Auto-denied: {req.request_id}")
                else:
                    channel.approve(req.request_id, "operator@example.com", "auto-approve")
                    print(f"[HITL] ✓ Auto-approved: {req.request_id}")
        except Exception as e:
            print(f"[HITL] auto_respond error: {e}")


if HITL_AUTO in ("approve", "deny"):
    print(f"[HITL] Auto-mode: {HITL_AUTO}")
    threading.Thread(target=auto_respond, daemon=True).start()
else:
    print("[HITL] Manual mode — approve via /v1/approve endpoint or set SHANI_HITL_AUTO=approve")

server = ShaniSidecarServer(gate=gate, host="0.0.0.0", port=8765)
print("Shani sidecar listening on 0.0.0.0:8765")
server.serve_forever()

