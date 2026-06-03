# Shani Conformance Profile

**Status:** Draft
**Applies to:** All Shani implementations (any language)

A system claiming to be "Shani-compatible" MUST satisfy the requirements in this document. The requirements are organized by interoperability level (L1–L3).

---

## L1: Schema Compatibility

### L1-1: DecisionProposal ingestion

An L1-compatible implementation MUST accept `DecisionProposal` objects conforming to `spec/proposal-schema.json`.

- MUST reject proposals missing any required field
- MUST reject proposals where `decision_id` is not a valid UUID
- MUST reject proposals where `confidence` is outside [0.0, 1.0]
- MUST reject proposals where `blast_radius` is not a known enum value
- MUST NOT reject proposals for unknown optional fields (forward compatibility)

### L1-2: ADO production

An L1-compatible implementation MUST produce `AuthorizedDecisionObject` objects conforming to `spec/ado-schema.json`.

- `decision_id` MUST match the originating `DecisionProposal.decision_id`
- `authorized_dsal` MUST be in [0, 4]
- `expires_at` MUST be after `issued_at`
- `nonce` MUST be a 64-character lowercase hex string (32 random bytes)
- `proposal_hash` MUST be a 64-character lowercase hex string

### L1-3: ADO ingestion

An L1-compatible implementation MUST:
- Reject ADOs where `expires_at <= now()`
- Reject ADOs where `authorized_dsal` > configured `max_authorized_dsal`
- Reject ADOs that have been previously executed (nonce replay prevention)

---

## L2: Signature Compatibility

### L2-1: Proposal hash

An L2-compatible implementation MUST compute `proposal_hash` using exactly the algorithm in `spec/canonicalization.md §2`.

- Only the fields listed in §2 are included
- Keys are sorted lexicographically
- `datetime` fields use `.isoformat()` format (`+00:00` suffix for UTC)
- Output is a lowercase SHA-256 hex digest (64 chars)

### L2-2: ADO signature payload

An L2-compatible implementation MUST compute the signature payload using exactly the algorithm in `spec/canonicalization.md §3`.

- `delegation_rules.allowed_sub_decisions` MUST be sorted
- `propagated_constraints` MUST be sorted
- `signature` itself MUST be excluded from the payload

### L2-3: Signature algorithm

An L2-compatible implementation MUST:
- Support Ed25519 signature verification (REQUIRED for L2)
- Support HMAC-SHA256 verification (permitted as fallback in development/testing only)

An L2-compatible implementation SHOULD:
- Support `signature_chain` verification (ADO v5.2)

### L2-4: Signature verification

An L2-compatible implementation MUST verify the ADO `signature` before acting on any ADO.

A failed verification MUST:
- Cause execution to halt immediately
- Log the verification failure with the ADO `decision_id`
- NOT produce a partial execution

---

## L3: Posture Compatibility

### L3-1: PostureEngine

An L3-compatible implementation MUST implement the two-layer PostureEngine defined in `spec/shani-v0.4.md §8.4`.

- Layer 1 MUST be deterministic (no LLM)
- Layer 1 MUST complete before any RiskPipeline evaluation
- Layer 2 MAY use semantic evaluation
- An AMBIGUOUS result MUST produce `PostureRefinementRequest`, never `DeniedDecision`

### L3-2: propagated_constraints validation

An L3-compatible implementation MUST validate `propagated_constraints` from incoming cross-org ADOs against its own PostureEngine.

- Unknown constraint vocabulary MUST produce AMBIGUOUS, not PASS
- AMBIGUOUS cross-org ADOs MUST return `PostureRefinementRequest` to the originating principal

### L3-3: UserPosture registration

An L3-compatible implementation MUST reject `UserPosture` objects that:
- Violate `OrgPolicy.absolute_constraints`
- Lack a `simulation_ref`

### L3-4: PostureSimulation

An L3-compatible implementation MUST run `PostureSimulation` before accepting a new or updated `UserPosture` from a principal.

---

## MUST FAIL test cases

Implementations MUST reject the following inputs:

| Input | Reason | Expected output |
|---|---|---|
| ADO where `expires_at` < `now()` | Expired | `DeniedDecision` / rejection |
| ADO reused (same `nonce`) | Replay attack | `DeniedDecision` / rejection |
| ADO with missing `propagated_constraints` in cross-org context | Spec §8.8 | AMBIGUOUS / `PostureRefinementRequest` |
| ADO with tampered `authority` field | Signature mismatch | Verification error |
| ADO with `authorized_dsal >= delegation_rules.max_child_dsal` | Schema invariant | Rejection at construction |
| Proposal with absent `decision_type` | Required field | Schema validation error |
| `UserPosture` without `simulation_ref` | §8.6 | Registration rejection |
| `UserPosture` exceeding `OrgPolicy.absolute_constraints` | §8.3 | Registration rejection |

## MUST PASS test cases

| Input | Expected output |
|---|---|
| Valid ADO with unexpired timestamp and valid signature | Execution permitted |
| Valid posture refinement request followed by updated posture | Second proposal reaches RiskPipeline |
| Delegation ADO with `max_child_dsal < authorized_dsal` | Child ADO issuance permitted |
| Cross-org ADO with recognized `propagated_constraints` | PostureEngine validates successfully |
