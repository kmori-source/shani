# RFC-0002: Propagated Constraints for Cross-Organizational ADO Chains

**Status:** Active
**Author(s):** Shani Working Group
**Created:** 2026-05
**Last updated:** 2026-05

---

## Summary

This RFC documents the design rationale, protocol, and open questions for `propagated_constraints` — the mechanism introduced in ADO v5.1 to address Cross-Organizational Chain Dilution. When an ADO crosses organizational boundaries, the originating principal's posture constraints are embedded in the ADO as a signed, cryptographically immutable field, propagating through the entire delegation chain.

---

## Motivation

### Cross-organizational Chain Dilution

Consider a multi-organization supply chain:

```
Alpha Corp → Beta LLC → Gamma GmbH → Delta SA
```

Principal A at Alpha Corp authorizes agent Alpha-Agent with a `UserPosture` that declares `target_scope: "domestic-only"`. Alpha-Agent generates an ADO and delegates to Beta-Agent. Beta-Agent re-delegates to Gamma-Agent, and so on.

Under ADO v5.0 (without propagated_constraints):

1. Alpha's ADO carries `origin_org: "alpha-corp"` but no constraints from Alpha's posture.
2. Beta receives the ADO and issues a child ADO to Gamma.
3. At each hop, the originating constraint (`domestic-only`) is not mechanically enforced — it depends on Beta, Gamma, and Delta each independently honoring Alpha's stated intent.
4. By the time the ADO reaches Delta's agent, the constraint is effectively lost. Delta has no cryptographic evidence that Alpha intended to restrict the action to domestic operations.

This is **Chain Dilution**: the originating constraint is diluted out of existence through the delegation chain, even though the ultimate execution might violate Alpha's explicitly stated intent.

### Why this matters for governance

Chain Dilution is not a theoretical concern. It is the default failure mode of any delegation system where:
- Constraints are advisory (documented but not mechanically enforced)
- Each hop in the chain is a separate organization with its own governance
- The originating principal has no visibility into terminal actions

In the supply chain scenario: Alpha's principal declares `domestic-only`, signs the posture, and believes they have constrained the action space. In practice, if the constraint is not embedded in the cryptographic chain, it provides no protection.

### The propagated_constraints solution

`propagated_constraints` embeds Alpha's posture constraints as a signed field in the ADO itself. Because the field is part of the canonical signature payload (`spec/canonicalization.md §3`), any modification breaks the ADO signature. The constraint travels with the ADO through every delegation hop and is cryptographically immutable.

When Delta's Shani instance receives an ADO, it can validate `propagated_constraints` against its own PostureEngine. If the validation fails (constraint violated or vocabulary unrecognized), the ADO is AMBIGUOUS — it cannot be acted upon without the originating principal's explicit intervention.

---

## Detailed Design

### ADO v5.1 additions

```
AuthorizedDecisionObject (v5.1)
  ...all v5.0 fields...
  propagated_constraints: list[string]   # constraints from originating principal's UserPosture
  origin_org:             string | null  # identifier of the originating organization
```

**Encoding:** `propagated_constraints` is a list of strings encoding constraint key-value pairs. The encoding format is `"key:value"`, e.g.:

```json
{
  "propagated_constraints": [
    "target_scope:domestic-only",
    "max_blast_radius:limited",
    "reversibility_required:true"
  ]
}
```

The list MUST be sorted lexicographically before being included in the signature payload (see `spec/canonicalization.md Rule CJ-7`).

### Issuance protocol

When issuing an ADO that will cross organizational boundaries:

1. The issuing Shani MUST embed `propagated_constraints` derived from the authorizing principal's `UserPosture`.
2. The derivation maps `PostureConstraints` fields to the string encoding:
   - `target_scope` → `"target_scope:{value}"`
   - `max_blast_radius` → `"max_blast_radius:{value}"`
   - `reversibility_required` → `"reversibility_required:{true|false}"`
   - `minimum_evidence` → `"minimum_evidence:{integer}"`
3. `origin_org` MUST be set to the originating organization's identifier.
4. The fields MUST be included in the signature payload before signing.

**Example:**
```python
if proposal.origin_org or is_cross_org_transition(proposal):
    propagated = derive_propagated_constraints(principal.posture)
    ado = AuthorizedDecisionObject(
        ...,
        propagated_constraints=propagated,
        origin_org=config.org_id,
    )
```

### Receiving protocol

When a Shani instance receives an ADO with non-empty `propagated_constraints`:

1. Verify the ADO signature first. A failed signature MUST reject the ADO before any constraint validation.
2. For each constraint in `propagated_constraints`:
   a. Parse the `key:value` encoding.
   b. If the key is recognized, validate it against the proposal using the same PostureEngine Layer 1 logic.
   c. If the key is **unrecognized**, treat the entire ADO as AMBIGUOUS (not PASS — fail-closed).
3. If all constraints are satisfied: proceed with normal evaluation.
4. If any constraint fails: REJECT (Layer 1 equivalent).
5. If any constraint is unrecognized: AMBIGUOUS → `PostureRefinementRequest` to the originating principal.

### `cross_org_min_dsal`

`OrgPolicy.absolute_constraints.cross_org_min_dsal` sets the minimum D-SAL for any ADO that crosses organizational boundaries. Default MUST be 4 (Board-level authorization, HITL required).

This acts as a mandatory escalation gate for all cross-org transitions, independent of the specific proposal's computed D-SAL. A cross-org ADO at D-SAL 2 that would normally not require HITL still requires Board-level authorization under this policy.

**Rationale:** Cross-org operations have external accountability implications that cannot be captured by the internal RiskPipeline alone. The elevated D-SAL requirement ensures that a human at the appropriate authority level reviews all cross-org transitions.

### Constraint propagation through delegation chains

When a child ADO is issued from a cross-org parent ADO:

1. The child ADO MUST inherit all `propagated_constraints` from the parent ADO.
2. The child ADO MAY add additional constraints (narrowing), but MUST NOT remove constraints from the parent (constraint monotonicity).
3. The receiving Shani at each hop validates both inherited and added constraints.

This ensures the originating constraint propagates through the entire chain, regardless of chain length.

**Chain example:**
```
Alpha issues ADO₁: propagated_constraints=["target_scope:domestic-only", "max_blast_radius:limited"]
  → Beta issues ADO₂ (child of ADO₁): propagated_constraints=["target_scope:domestic-only", "max_blast_radius:limited", "environment:staging-only"]
    → Gamma issues ADO₃ (child of ADO₂): propagated_constraints=["target_scope:domestic-only", "max_blast_radius:limited", "environment:staging-only"]
      → Delta validates ADO₃: all three constraints are validated before execution
```

---

## Conformance impact

New normative requirements (§8.8 of `spec/shani-v0.4.md`):

| Test | Expected behavior |
|---|---|
| Cross-org ADO without `propagated_constraints` | Receiving Shani treats as AMBIGUOUS |
| `propagated_constraints` field modified after signing | Signature verification fails |
| Receiving Shani encounters unrecognized constraint key | AMBIGUOUS (not PASS) |
| `cross_org_min_dsal` exceeded | ADO rejected, elevated authority required |
| Child ADO missing parent's propagated_constraints | Schema validation error |

---

## Alternatives considered

### Alternative A: Shared posture registry

A shared, publicly accessible registry where organizations publish their posture declarations. Receiving organizations look up the originating organization's posture and validate against it directly.

**Rejected because:**
- Requires a trusted third-party registry operator (who governs the governors?)
- Introduces a live dependency on an external service in the authorization path
- Posture declarations may be private (an organization may not wish to publish its internal constraints)
- Network availability affects the authorization path

### Alternative B: Posture embedding (full UserPosture in ADO)

Instead of a string encoding of constraints, embed the full `UserPosture` JSON object in the ADO.

**Rejected because:**
- Substantially increases ADO size (UserPosture includes history, intent_statement, simulation_ref — none relevant to receiving organizations)
- The full UserPosture contains internal organizational data that may be sensitive
- The minimal string encoding is sufficient for validation purposes

### Alternative C: Out-of-band constraint negotiation

Organizations negotiate constraints bilaterally before any cross-org operations begin. At operation time, only the `origin_org` field is needed; the receiving organization looks up the pre-negotiated constraints in their own configuration.

**Rejected because:**
- Requires advance coordination for every new cross-org relationship
- Does not handle runtime constraint changes (if Alpha updates their posture, the pre-negotiated constraint becomes stale)
- The per-ADO embedding creates a cryptographic audit trail that out-of-band negotiation does not

---

## Open questions

- [ ] **Constraint vocabulary standardization:** The `propagated_constraints` encoding is currently `"key:value"` strings based on `PostureConstraints` field names. There is no shared vocabulary standard across organizations. An organization could use `"target_scope:domestic"` and another could use `"geographic_limit:domestic"` — both meaningful but not interchangeable. RFC-0002 does not solve the vocabulary problem; it only solves the cryptographic propagation problem. A future RFC should address constraint vocabulary standardization.

- [ ] **Constraint monotonicity enforcement:** The design requires that child ADOs MUST NOT remove constraints from the parent (monotonicity). The current implementation does not enforce this at the schema level — it relies on the issuing Shani to preserve parent constraints. Should monotonicity be enforced cryptographically (e.g., each constraint is individually signed rather than as a list)?

- [ ] **Constraint expiry:** Currently, `propagated_constraints` have no independent expiry; they expire with the ADO. If Alpha's posture changes mid-chain (e.g., they add a new constraint after ADO₁ is issued), ADO₁ and its children reflect the old posture. Should there be a mechanism for the originating organization to revoke or update propagated constraints mid-chain?

- [ ] **Constraint granularity:** `PostureConstraints` has four fields. Future posture dimensions (e.g., `data_sensitivity_max`, reserved in §8.2) will add more. Should `propagated_constraints` propagate all posture fields, or only a designated subset?

- [ ] **Privacy:** Cross-org ADOs reveal the originating organization's posture constraints to all downstream organizations. This may be undesirable if constraints are competitively sensitive (e.g., `target_scope:supplier-X-only` reveals a business relationship). Should there be a privacy-preserving variant (e.g., zero-knowledge proof of constraint satisfaction)?

---

## References

- [Shani Spec §8.8 (Cross-Organizational Binding)](../spec/shani-v0.4.md)
- [Threat Model T18 (Cross-Org Constraint Mismatch)](../spec/threat-model.md)
- [Canonicalization Spec §3 (ADO signature payload)](../spec/canonicalization.md)
- [RFC-0001: PostureEngine Design](RFC-0001-posture-engine.md)
- [Posture Schema](../spec/posture-schema.json)
