"""
examples/k8s/admission_webhook.py

Shani Kubernetes admission webhook server.

Intercepts AdmissionReview requests from the K8s API server and evaluates
each mutating/validating request through Shani's governance pipeline.

Production requirements:
  - TLS certificate (K8s requires HTTPS for webhooks)
  - Proper agent registry in policy/authority.yaml
  - Persistent nonce store (FileNonceStore) to survive pod restarts

Install:
    pip install fastapi uvicorn pyyaml shani[core]

Run (dev):
    uvicorn admission_webhook:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile /certs/tls.key --ssl-certfile /certs/tls.crt
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

# FastAPI is an optional dependency — only needed for the HTTP server.
# The Shani core has no dependency on it.
try:
    from fastapi import FastAPI, Request, Response
    import uvicorn

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

from shani import (
    ShaniEvaluator,
    StaticAuthorityProvider,
    DecisionType,
    BlastRadius,
    DeniedDecision,
)
from shani.authority.policy import DecisionPolicyProvider, AgentIdentity
from shani.schemas.decision import DecisionProposal, DecisionScope, EvidenceItem

logger = logging.getLogger("shani.k8s.webhook")

# ── Evaluator setup ──────────────────────────────────────────────────────────


def build_evaluator() -> ShaniEvaluator:
    agents = {
        "gitops-agent/v1": AgentIdentity(
            agent_id="gitops-agent/v1",
            granted_dsal=2,
            allowed_decision_types=frozenset(["configuration_change", "data_access"]),
        ),
        "security-scanner/v1": AgentIdentity(
            agent_id="security-scanner/v1",
            granted_dsal=1,
            allowed_decision_types=frozenset(["remediation"]),
        ),
        "sre-automation/v1": AgentIdentity(
            agent_id="sre-automation/v1",
            granted_dsal=3,
            allowed_decision_types=frozenset(
                [
                    "configuration_change",
                    "remediation",
                    "network_action",
                ]
            ),
        ),
    }
    return ShaniEvaluator(
        authority_provider=StaticAuthorityProvider(max_dsal=3),
        decision_policy=DecisionPolicyProvider(agent_registry=agents),
    )


_EVALUATOR = build_evaluator()


# ── Proposal builder from AdmissionReview ───────────────────────────────────

_OPERATION_TO_DECISION_TYPE: dict[str, DecisionType] = {
    "CREATE": DecisionType.CONFIGURATION_CHANGE,
    "UPDATE": DecisionType.CONFIGURATION_CHANGE,
    "DELETE": DecisionType.REMEDIATION,
}

_OPERATION_TO_BLAST: dict[str, BlastRadius] = {
    "CREATE": BlastRadius.LIMITED,
    "UPDATE": BlastRadius.LIMITED,
    "DELETE": BlastRadius.SIGNIFICANT,
}


def admission_review_to_proposal(review: dict[str, Any]) -> DecisionProposal:
    req = review.get("request", {})
    operation = req.get("operation", "CREATE")
    resource = req.get("resource", {})
    namespace = req.get("namespace", "default")
    name = req.get("name", "unknown")
    kind = resource.get("resource", "unknown")
    user_info = req.get("userInfo", {})
    agent_id = user_info.get("username", "unknown-agent")

    resource_str = f"k8s:{namespace}/{kind}/{name}"

    return DecisionProposal(
        decision_type=_OPERATION_TO_DECISION_TYPE.get(operation, DecisionType.CONFIGURATION_CHANGE),
        proposed_by=agent_id,
        description=f"{operation} {kind}/{name} in namespace {namespace}",
        target=resource_str,
        scope=DecisionScope(
            asset_ids=[resource_str],
            resource_types=[f"k8s:{kind}"],
            geographic_boundary=os.environ.get("CLUSTER_REGION", "unknown"),
        ),
        evidence=[
            EvidenceItem(
                source="k8s-admission",
                content=f"K8s API server admission request: {operation} {kind}/{name}",
                confidence=0.8,
            )
        ],
        confidence=0.8,
        reversibility=(operation != "DELETE"),
        blast_radius=_OPERATION_TO_BLAST.get(operation, BlastRadius.LIMITED),
        expires_at=datetime.now(tz=timezone.utc) + timedelta(seconds=30),
    )


def evaluate_admission(review: dict[str, Any]) -> dict[str, Any]:
    uid = review.get("request", {}).get("uid", "")
    try:
        proposal = admission_review_to_proposal(review)
        result = _EVALUATOR.evaluate(proposal)
        if isinstance(result, DeniedDecision):
            summary = result.to_human_summary()
            return {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": False,
                    "status": {
                        "code": 403,
                        "message": f"Shani denied: {summary['reason']}",
                    },
                },
            }
        # Authorized: annotate the object with ADO metadata
        ado = result
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": True,
                "patchType": "JSONPatch",
                "patch": _ado_annotation_patch(ado),
            },
        }
    except Exception as exc:
        logger.error("Admission evaluation failed: %s", exc, exc_info=True)
        # Fail-closed: deny on internal errors
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {"code": 500, "message": "Shani internal error"},
            },
        }


def _ado_annotation_patch(ado: object) -> str:
    import base64 as _b64

    patches = [
        {
            "op": "add",
            "path": "/metadata/annotations",
            "value": {},
        },
        {
            "op": "add",
            "path": "/metadata/annotations/shani.io~1decision-id",
            "value": ado.decision_id,
        },
        {
            "op": "add",
            "path": "/metadata/annotations/shani.io~1authorized-dsal",
            "value": str(ado.authorized_dsal),
        },
        {
            "op": "add",
            "path": "/metadata/annotations/shani.io~1authority",
            "value": ado.authority,
        },
    ]
    return _b64.b64encode(json.dumps(patches).encode()).decode()


# ── FastAPI app ──────────────────────────────────────────────────────────────

if _HAS_FASTAPI:
    app = FastAPI(title="Shani K8s Admission Webhook")

    @app.post("/validate")
    async def validate(request: Request) -> Response:
        body = await request.json()
        result = evaluate_admission(body)
        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    if __name__ == "__main__":
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=int(os.environ.get("PORT", "8443")),
        )
else:
    print("FastAPI not installed. Run: pip install fastapi uvicorn")
    print("For demo without HTTP server, run: python scenario.py")
