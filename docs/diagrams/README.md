# Shani Architecture Diagrams

This directory contains architecture, flow, and threat diagrams for the Shani decision governance layer.

## Contents

| File | Description |
|---|---|
| `evaluation-pipeline.md` | End-to-end decision evaluation flow (Mermaid) |
| `dis-state-machine.md` | DIS state machine transitions (Mermaid) |
| `trust-boundary.md` | Trust boundary and component overview (Mermaid) |
| `signature-chain.md` | ADO signature chain structure (Mermaid) |
| `cross-org-flow.md` | Cross-organizational ADO propagation (Mermaid) |

All diagrams are authored in [Mermaid](https://mermaid.js.org/) for render-on-GitHub compatibility.

## Evaluation Pipeline

See `evaluation-pipeline.md` for the complete flow from `DecisionProposal` to `AuthorizedDecisionObject`.

High-level overview:

```
Agent
 └── DecisionProposal
       ↓
 ShaniEvaluator
   1. Kill Switch check         → DeniedDecision if active
   2. DIS state check           → DeniedDecision if VIOLATED
   3. Agent registry check      → DeniedDecision if unregistered
   4. PostureEngine (v0.4)      → PostureRejection / PostureRefinementRequest / PASS
   5. RiskPipeline
      ├── EvidenceEvaluator     → quality_score
      ├── RiskAssessor          → risk_score
      ├── RuleEngine            → hard denials
      └── DecisionSpaceAnalyzer → framing_risk
   6. DSALMapper                → effective_dsal
   7. HITL gate (if needed)     → human approve/deny
   8. ADO issuance              → AuthorizedDecisionObject
       ↓
 ExecutionBoundary
   - verify_binding()           → signature + nonce + expiry
   - issue_capability()         → Capability token
       ↓
 Agent executes capability
 └── register_executed(ado)    → nonce consumed
```
