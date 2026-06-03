# Kubernetes Admission Control — Shani Governance

This example shows how to use Shani as a Kubernetes admission webhook.
Any agent that modifies cluster state (e.g., deletes pods, changes resource
limits, creates new deployments) must first obtain an ADO from Shani.

## Architecture

```
kubectl / GitOps / Agent
    │
    ▼
Kubernetes API Server
    │  AdmissionReview request
    ▼
Shani Admission Webhook  ←── policy/authority.yaml
    │
    ├─ ALLOW  → Issue ADO, attach as annotation
    └─ DENY   → Return admission error (agent blocked)
```

## Files

| File | Description |
|---|---|
| `admission_webhook.py` | FastAPI webhook server (production: use your own TLS) |
| `scenario.py` | End-to-end demo (no real K8s needed) |
| `k8s-webhook-config.yaml` | ValidatingWebhookConfiguration to register with K8s |
| `policy.yaml` | Agent authority policy for cluster operations |

## Quick Start (demo, no real K8s needed)

```bash
pip install shani[core]
python scenario.py
```

## Production Deployment

```bash
# 1. Deploy the webhook server (TLS required by K8s)
docker build -t shani-webhook .
kubectl apply -f k8s-webhook-config.yaml

# 2. The webhook runs as a pod in the cluster
kubectl apply -f webhook-deployment.yaml
```
