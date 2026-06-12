# Trust Boundary

Trust zones and component boundaries within the Shani decision governance layer.

```mermaid
flowchart TB
    subgraph Untrusted["Untrusted Zone (Agent-side)"]
        Agent([Agent])
        DP[DecisionProposal]
        Agent -->|constructs| DP
    end

    subgraph Shani["Shani Evaluation Zone (Trusted)"]
        direction TB
        KS[Kill Switch]
        DIS[DIS Monitor]
        AR[Agent Registry]
        PE[PostureEngine]
        RP[RiskPipeline]
        DM[DSALMapper]
        HITL[HITL Gate]
        ADO_Issue[ADO Issuance\nEd25519 signed]

        KS --> DIS --> AR --> PE --> RP --> DM --> HITL --> ADO_Issue
    end

    subgraph Boundary["Execution Boundary (Enforcement Point)"]
        VB[verify_binding\nsignature + nonce + expiry]
        IC[issue_capability]
        NR[register_executed\nnonce consumed]
        VB -->|pass| IC
        IC --> NR
    end

    subgraph World["External World"]
        Res[(Resources\nAPIs / Files / Systems)]
    end

    DP -->|crosses trust boundary| KS
    ADO_Issue -->|signed ADO| VB
    IC -->|Capability| Agent
    Agent -->|cap.execute| Res

    classDef untrusted fill:#fde8e8,stroke:#c0392b
    classDef trusted fill:#e8f4e8,stroke:#27ae60
    classDef boundary fill:#e8eaf6,stroke:#3949ab
    classDef world fill:#fff9e6,stroke:#f39c12

    class Untrusted untrusted
    class Shani trusted
    class Boundary boundary
    class World world
```

## Zone definitions

| Zone | Trust level | What it contains |
|---|---|---|
| **Untrusted** | None — agent assertions are not trusted | `DecisionProposal` (all fields treated as claims to be verified) |
| **Shani Evaluation** | Fully trusted | Kill Switch, DIS, registry, PostureEngine, RiskPipeline, ADO signer |
| **Execution Boundary** | Fully trusted | `verify_binding`, `issue_capability`, nonce consumption |
| **External World** | Untrusted | APIs, file systems, external services |

## Trust crossing rules

| Crossing | Requirement |
|---|---|
| Agent → Shani | `DecisionProposal` schema validation; no agent-declared D-SAL accepted |
| Shani → Boundary | ADO must carry valid Ed25519 signature over canonical payload |
| Boundary → World | Only via `Capability` token issued by `ExecutionBoundary` |
| Cross-org (any) | `propagated_constraints` embedded and signed in ADO; `origin_org` set |

## What Shani does NOT trust

- Agent-declared `requested_dsal` — ignored; D-SAL is computed from risk
- Agent identity claims in proposal content — verified against agent registry
- Unsigned ADOs — `verify_binding` rejects any tampered or unsigned ADO
- Replayed ADOs — nonce store prevents any previously-executed ADO from re-entering
