# ADO Signature Chain

Structure of the ADO v5.2 signature chain for multi-principal signing.

```mermaid
sequenceDiagram
    participant Agent
    participant Shani as ShaniEvaluator
    participant Authority as Authority Signer
    participant Boundary as Boundary Signer

    Agent->>Shani: DecisionProposal
    Shani->>Shani: Compute canonical_payload(ADO minus signature)
    Shani->>Authority: Sign(canonical_payload)
    Authority->>Shani: ADOSignature{role="authority", signature_b64, public_key_b64}
    Shani->>Boundary: Sign(canonical_payload + prior_chain)
    Boundary->>Shani: ADOSignature{role="boundary", signature_b64, public_key_b64}
    Shani->>Shani: chain_hash = SHA256(canonical_chain_json)
    Shani->>Agent: ADO{signature=chain_hash, signature_chain={...}}

    Note over Agent: Before execution:
    Agent->>Agent: verify_binding(ado)\n→ recompute chain_hash\n→ verify each signature
```

## Canonical payload fields (signed by all)

```
decision_id
proposal_hash
authority
authorized_dsal
delegation_rules {allowed_sub_decisions, max_child_dsal, max_depth, max_children}
nonce
issued_at
expires_at
exec_context {decision_type, intent_binding, parent_decision_id, constraints}
propagated_constraints
origin_org
```

## Attacks prevented by full payload coverage

| Attack | Field that prevents it |
|---|---|
| Authority rewrite | `authority` in payload |
| D-SAL escalation | `authorized_dsal` in payload |
| Delegation loosening | all four `delegation_rules` fields |
| Execution drift | `exec_context.intent_binding.target` |
| Nonce stripping | `nonce` in payload |
| Expiry extension | `expires_at` in payload |
| Cross-org constraint mutation | `propagated_constraints` in payload |
