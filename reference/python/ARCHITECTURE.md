# Python Reference Implementation — Architecture

## Evaluation Pipeline

```
DecisionProposal (agent)
    │
    ▼
PostureEngine (shani/posture/engine.py)        — SPEC §8.4
    │  Layer 1: Static match (deterministic)
    │  Layer 2: Semantic evaluation
    │  → REJECT / AMBIGUOUS / PASS
    │
    ▼ (PASS only)
RiskPipeline (shani/risk/pipeline.py)          — SPEC §6
    │  EvidenceEvaluator → RiskAssessor → DSALCalculator → RulesEngine
    │  → PipelineResult (risk_score, effective_dsal, rule_result)
    │
    ▼
ShaniEvaluator (shani/core/evaluator.py)       — SPEC §5
    │  Checks: DIS state, authority, D-SAL ceiling, delegation rules
    │  → AuthorizedDecisionObject (ADO v5) | DeniedDecision
    │
    ▼ (ADO issued)
ExecutionBoundary (shani/boundary/capability.py) — SPEC §7.2
    │  verify_binding() → Capability
    │  Capability.execute(fn) → result
    │
    ▼
World (side-effecting action)
```

## DIS State Machine

```
VALID ──────► DEGRADED ──────► VIOLATED
  ▲               │
  └───────────────┘
    (VIOLATED → VALID: manual reset only via reset_to_valid())
```

Implemented in `shani/schemas/state.py::DISStateMachine`.

## ADO Signature Chain (v5.2)

```
authority_signature    (policy/human authority endorses D-SAL level)
    │
    ▼
boundary_signature     (Shani boundary certifies evaluation was performed)
    │
    ▼
agent_signature        (proposing agent binds its identity to the proposal)
    │
    ▼ (optional)
delegate_signature     (sub-agent signature for delegation chains)
```

Implemented in `shani/crypto/signing.py`.

## Key Invariants

1. **No ADO → no Capability → no execution** (SPEC §4.2)
2. **DIS VIOLATED → all proposals denied** (SPEC §4.4)
3. **Proposal hash bound to ADO** — any proposal mutation invalidates signature
4. **Nonce consumed on execution** — replay attacks fail even across restarts
5. **max_child_dsal < authorized_dsal** — escalation invariant enforced at issuance
