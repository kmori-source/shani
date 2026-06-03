# Evaluation Pipeline

End-to-end decision evaluation flow in Shani.

```mermaid
flowchart TD
    Agent([Agent]) --> |DecisionProposal| Eval

    subgraph Eval[ShaniEvaluator]
        KS{Kill Switch\nactive?}
        DIS{DIS ==\nVIOLATED?}
        REG{Agent\nregistered?}
        PE[PostureEngine\nv0.4]
        RP[RiskPipeline]
        DM[DSALMapper]
        HITL{HITL\nrequired?}
        ADO[Issue ADO]

        KS -->|Yes| D1[DeniedDecision]
        KS -->|No| DIS
        DIS -->|Yes| D2[DeniedDecision]
        DIS -->|No| REG
        REG -->|No| D3[DeniedDecision]
        REG -->|Yes| PE

        PE -->|REJECT| D4[PostureRejection]
        PE -->|AMBIGUOUS| D5[PostureRefinementRequest]
        PE -->|PASS| RP

        RP --> DM
        DM --> HITL

        HITL -->|Yes| HG[HITLGate]
        HG -->|Denied| D6[DeniedDecision]
        HG -->|Approved| ADO
        HITL -->|No| ADO
    end

    subgraph Boundary[ExecutionBoundary]
        VB[verify_binding]
        IC[issue_capability]
        VB -->|Fail| D7[Halt execution]
        VB -->|Pass| IC
    end

    ADO --> VB
    IC --> Execute([Agent executes\nCapability])
    Execute --> NR[register_executed\nnonce consumed]
```

## Stage descriptions

| Stage | Module | Purpose |
|---|---|---|
| Kill Switch | `shani/core/evaluator.py` | Immediate halt — all proposals denied |
| DIS check | `shani/integrity/` | Deny if DIS is VIOLATED or DEGRADED |
| Agent registry | `shani/authority/policy.py` | Deny if agent not in `policy/decision_policy.yaml` |
| PostureEngine | `shani/posture/engine.py` | v0.4 Binding Layer pre-filter |
| EvidenceEvaluator | `shani/risk/evidence.py` | Source trust → quality_score |
| RiskAssessor | `shani/risk/assessor.py` | Multi-dimensional risk_score (0.0–1.0) |
| RuleEngine | `shani/risk/rules.py` | Hard denials (irreversible critical, etc.) |
| DecisionSpaceAnalyzer | `shani/risk/decision_space.py` | Framing detection |
| DSALMapper | `shani/core/dsal.py` | risk_score → effective_dsal |
| HITLGate | `shani/hitl/gate.py` | Human approval if dsal >= threshold |
| verify_binding | `shani/boundary/hook.py` | Ed25519 signature + nonce + expiry |
| issue_capability | `shani/boundary/capability.py` | Capability token bound to ADO |
