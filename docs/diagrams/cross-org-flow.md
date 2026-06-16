# Cross-Organizational ADO Propagation

Flow for ADO propagation across organizational boundaries (ADO v5.1, Shani v0.4).

```mermaid
sequenceDiagram
    participant AgentA as Agent A\n(Org Alpha)
    participant ShaniA as Shani\n(Org Alpha)
    participant ShaniB as Shani\n(Org Beta)
    participant AgentB as Agent B\n(Org Beta)

    AgentA->>ShaniA: DecisionProposal\n{origin_org: "alpha", intent: "..."}

    ShaniA->>ShaniA: Evaluate (RiskPipeline, PostureEngine)
    ShaniA->>ShaniA: Embed propagated_constraints\nfrom Agent A's UserPosture
    Note over ShaniA: cross_org_min_dsal check\n(default: 4, HITL required)
    ShaniA->>ShaniA: HITL approval (D-SAL ≥ 4)
    ShaniA->>AgentA: ADO_A {origin_org="alpha",\npropagated_constraints=[...],\nsigned}

    AgentA->>ShaniB: DecisionProposal + ADO_A\n(cross-org handoff)

    ShaniB->>ShaniB: Verify ADO_A signature
    ShaniB->>ShaniB: Validate propagated_constraints\nagainst own PostureEngine

    alt constraints recognized and satisfied
        ShaniB->>ShaniB: Issue ADO_B\n{propagated_constraints inherited,\norigin_org="alpha"}
        ShaniB->>AgentB: ADO_B (inherits Alpha's constraints)
        AgentB->>AgentB: execute within\npropagated constraint ceiling
    else constraint vocabulary unknown
        ShaniB->>AgentA: PostureRefinementRequest\n(AMBIGUOUS — not DENIED)
        Note over AgentA,ShaniB: Agent A must refine\nposture and resubmit
    else propagated_constraints missing or tampered
        ShaniB->>AgentA: PostureRefinementRequest\n(AMBIGUOUS — missing constraints)
    end
```

## Normative requirements (v0.4)

| Requirement | Description |
|---|---|
| `cross_org_min_dsal` | Minimum D-SAL for any cross-org ADO. Default **4** (Board-level, HITL required). |
| Embed on issue | Issuing Shani MUST embed `propagated_constraints` from principal's `UserPosture`. |
| Validate on receipt | Receiving Shani MUST validate `propagated_constraints` against its own PostureEngine. |
| Unknown vocabulary | Receiving Shani that cannot validate constraints MUST return `PostureRefinementRequest` (AMBIGUOUS), never silently pass. |
| Signature coverage | `propagated_constraints` and `origin_org` MUST be in the canonical signed payload. Mutation breaks verification. |
| Missing constraints | Cross-org ADO without `propagated_constraints` MUST be treated as AMBIGUOUS. |

## Constraint propagation invariant

```
Alpha declares: target_scope = "domestic-only"
                ↓ embedded in ADO_A (signed)
Beta receives:  propagated_constraints includes target_scope
                ↓ validated by Beta's PostureEngine
Delta executes: international action BLOCKED
                (constraint ceiling inherited through A→B→C→D chain)
```

Alpha's constraint is cryptographically bound at issuance. No intermediate organization (Beta, Gamma, Delta) can remove or weaken it without breaking the ADO signature.

## ADO v5.1 cross-org fields

| Field | Type | Purpose |
|---|---|---|
| `propagated_constraints` | `list[string]` | Constraints from originating principal's UserPosture |
| `origin_org` | `string` | Identifier of the originating organization |
