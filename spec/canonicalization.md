# Shani Canonicalization Specification

**Status:** Normative
**Applies to:** ADO v5+ (Shani v0.3+)

This document defines the canonical serialization format for all objects whose integrity depends on cryptographic verification. Implementations MUST produce identical byte sequences from identical inputs for signatures to be interoperable.

> **Why this matters:** Canonical JSON is the only input to the signature functions. If two implementations serialize the same ADO differently (e.g., different key ordering, different datetime formatting), they will compute different signatures, and cross-implementation verification will fail. This is the class of bug referred to as "binding 系 protocol はここで死にます."

---

## 1. Canonical JSON Rule Set

Shani uses **Deterministic JSON** (a restricted subset of JSON) as its canonical format.

### Rule CJ-1: Key ordering

All object keys MUST be sorted lexicographically by Unicode code point. This matches `json.dumps(obj, sort_keys=True)` in Python and `JSON.stringify` with a custom comparator in JavaScript.

```
✓  {"a": 1, "b": 2, "c": 3}
✗  {"c": 3, "a": 1, "b": 2}
```

### Rule CJ-2: No whitespace

The canonical form contains no spaces, newlines, or indentation. Separators are `:` and `,` (no spaces).

```
✓  {"decision_id":"abc","expires_at":"2026-05-01T00:00:00+00:00"}
✗  {"decision_id": "abc", "expires_at": "2026-05-01T00:00:00+00:00"}
```

### Rule CJ-3: String encoding

All strings MUST be UTF-8 encoded. Control characters MUST be escaped using `\uXXXX` notation. No other escaping is permitted unless required by the JSON specification.

### Rule CJ-4: Number encoding

Integers MUST be represented without decimal points or exponents.

```
✓  {"authorized_dsal": 2}
✗  {"authorized_dsal": 2.0}
✗  {"authorized_dsal": 2e0}
```

Floating-point values are not used in any signed field. If a future field requires floating-point, it MUST be serialized as a JSON number with no trailing zeros.

### Rule CJ-5: Datetime encoding

All datetime values MUST be serialized as ISO 8601 strings **with timezone offset**. UTC datetimes MUST use the `+00:00` suffix form as produced by Python's `datetime.isoformat()` with timezone-aware objects.

```
✓  "2026-05-01T09:00:00+00:00"
✗  "2026-05-01T09:00:00Z"
✗  "2026-05-01T09:00:00"
✗  "2026-05-01 09:00:00+00:00"
```

**Note:** Python's `datetime.isoformat()` on a UTC-aware datetime produces `+00:00`, not `Z`. Implementations in other languages MUST match this format exactly.

### Rule CJ-6: Null values

Null values MUST be represented as JSON `null`, not as absent keys.

```
✓  {"origin_org": null}
✗  {}   (key omitted)
```

Exception: keys that are explicitly listed as absent from the canonical payload (see Section 3) MUST be omitted entirely.

### Rule CJ-7: List ordering

List values retain their natural order **unless the specification explicitly requires sorting**. The following fields MUST be sorted before serialization:

- `delegation_rules.allowed_sub_decisions` — sorted lexicographically
- `propagated_constraints` — sorted lexicographically

```python
# Correct
"delegation_rules": {
    "allowed_sub_decisions": sorted(dr.allowed_sub_decisions),
    ...
}
"propagated_constraints": sorted(ado.propagated_constraints)
```

---

## 2. Proposal Canonical Hash

`DecisionProposal.canonical_hash()` produces the `proposal_hash` embedded in every ADO.

### Payload definition

```json
{
  "decision_id":   "<string: UUID>",
  "decision_type": "<string: enum value>",
  "proposed_by":   "<string>",
  "description":   "<string>",
  "target":        "<string>",
  "reversibility": "<boolean>",
  "blast_radius":  "<string: enum value>",
  "expires_at":    "<string: ISO 8601 | null>"
}
```

### Excluded fields

The following proposal fields are **NOT** included in the canonical hash:

- `scope` — not part of the authorization commitment
- `evidence` — mutable and evaluated separately by RiskPipeline
- `confidence` — heuristic, not security-critical
- `parent_decision_id` — tracked via ADO delegation chain
- `assumptions` — tracked via DIS, not the ADO
- `delegation` — captured in `delegation_rules` at ADO issuance
- `origin_org` — present in the ADO directly

**Rationale:** The canonical hash commits only to the fields that define *what action is being requested*. Auxiliary fields that affect evaluation but not identity are excluded to avoid fragile hashes that change as proposals are enriched during evaluation.

### Computation

```python
import hashlib, json

def canonical_hash(proposal) -> str:
    data = {
        "decision_id":   proposal.decision_id,
        "decision_type": proposal.decision_type.value,
        "proposed_by":   proposal.proposed_by,
        "description":   proposal.description,
        "target":        proposal.target,
        "reversibility": proposal.reversibility,
        "blast_radius":  proposal.blast_radius.value,
        "expires_at":    proposal.expires_at.isoformat() if proposal.expires_at else None,
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
```

Output: 64-character lowercase hex string (SHA-256 hex digest).

---

## 3. ADO Canonical Signature Payload

The ADO signature payload is the exact input to the signing function.

### Payload definition

```json
{
  "decision_id":     "<string: UUID>",
  "proposal_hash":   "<string: 64-char hex>",
  "authority":       "<string>",
  "authorized_dsal": "<integer: 0–4>",
  "delegation_rules": {
    "allowed_sub_decisions": ["<sorted list of DecisionType strings>"],
    "max_child_dsal": "<integer>",
    "max_depth":      "<integer>",
    "max_children":   "<integer>"
  },
  "nonce":      "<string: 64-char hex>",
  "issued_at":  "<string: ISO 8601>",
  "expires_at": "<string: ISO 8601>",
  "exec_context": {
    "decision_type": "<string: enum value>",
    "intent_binding": {
      "intent":          "<string>",
      "target":          "<string>",
      "scope_summary":   "<string>",
      "expected_effect": "<string>",
      "reversibility":   "<boolean>"
    },
    "parent_decision_id": "<string: UUID | null>",
    "constraints":        "<object>"
  },
  "propagated_constraints": ["<sorted list of strings>"],
  "origin_org": "<string | null>"
}
```

### Excluded ADO fields

The following ADO fields are excluded from the signature payload:

- `signature` itself — cannot be self-referential
- `signature_chain` — covered by the chain binding mechanism (Section 4)
- `exec_context.rollback_policy` — covered indirectly via `proposal_hash`; excluded to avoid serialization ambiguity with nested nullable objects

### Computation

```python
import json, hashlib

def ado_signature_payload(ado) -> dict:
    ec = ado.exec_context
    dr = ado.delegation_rules
    return {
        "decision_id":     ado.decision_id,
        "proposal_hash":   ado.proposal_hash,
        "authority":       ado.authority,
        "authorized_dsal": ado.authorized_dsal,
        "delegation_rules": {
            "allowed_sub_decisions": sorted(dr.allowed_sub_decisions),
            "max_child_dsal":        dr.max_child_dsal,
            "max_depth":             dr.max_depth,
            "max_children":          dr.max_children,
        },
        "nonce":      ado.nonce,
        "issued_at":  ado.issued_at.isoformat(),
        "expires_at": ado.expires_at.isoformat(),
        "exec_context": {
            "decision_type": ec.decision_type.value,
            "intent_binding": {
                "intent":          ec.intent_binding.intent,
                "target":          ec.intent_binding.target,
                "scope_summary":   ec.intent_binding.scope_summary,
                "expected_effect": ec.intent_binding.expected_effect,
                "reversibility":   ec.intent_binding.reversibility,
            },
            "parent_decision_id": ec.parent_decision_id,
            "constraints":        ec.constraints,
        },
        "propagated_constraints": sorted(ado.propagated_constraints),
        "origin_org":             ado.origin_org,
    }

def compute_signature(payload: dict, private_key) -> str:
    canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    return private_key.sign(canonical_bytes)  # Ed25519
```

---

## 4. Signature Chain Canonicalization

When `signature_chain` is present (ADO v5.2+), each signer covers:

1. The canonical payload (Section 3)
2. All prior signatures in the chain

### Chain entry format

```json
{
  "signatures": [
    {
      "principal_id":    "<string>",
      "role":            "<authority | boundary | agent | delegate>",
      "signature_b64":   "<base64-encoded 64-byte Ed25519 signature>",
      "signed_at":       "<string: ISO 8601>",
      "public_key_b64":  "<base64-encoded 32-byte public key>"
    }
  ]
}
```

### Per-signer computation

```python
def sign_with_chain(payload: dict, prior_chain: dict, private_key) -> bytes:
    combined = {
        "payload":     payload,
        "prior_chain": prior_chain,
    }
    combined_bytes = json.dumps(combined, sort_keys=True).encode("utf-8")
    return private_key.sign(combined_bytes)
```

### Chain hash

The `ADO.signature` field stores the SHA-256 hex digest of the canonical chain:

```python
def chain_hash(chain: dict) -> str:
    chain_json = json.dumps(chain, sort_keys=True)
    return hashlib.sha256(chain_json.encode()).hexdigest()
```

---

## 5. UserPosture Canonical Content

`UserPosture.canonical_content()` produces the payload that is signed by the principal.

```python
def canonical_content(posture) -> dict:
    return {
        "version":          posture.version,
        "principal_id":     posture.principal_id,
        "signed_at":        posture.signed_at.isoformat(),
        "intent_statement": posture.intent_statement,
        "simulation_ref":   posture.simulation_ref,
        "constraints": {
            "target_scope":           posture.constraints.target_scope,
            "max_blast_radius":       posture.constraints.max_blast_radius,
            "reversibility_required": posture.constraints.reversibility_required,
            "minimum_evidence":       posture.constraints.minimum_evidence,
        },
    }
```

`posture_signature` is excluded from the canonical form (same principle as ADO `signature`).

---

## 6. Security Properties

### What the proposal hash prevents

- **Fake ADO (T1):** An attacker cannot construct an ADO for a proposal they did not submit, because `SHA256(canonical_proposal)` is not reversible. The ADO is bound to the exact bytes of the original proposal.

### What the ADO signature prevents

- **Authority rewrite:** `authority` is in the signed payload; altering it breaks the signature.
- **D-SAL escalation:** `authorized_dsal` is in the signed payload.
- **Delegation loosening:** All four `delegation_rules` fields are in the signed payload.
- **Execution drift (T6):** `exec_context.intent_binding.target` is in the signed payload. An agent approved to "isolate host A" cannot claim authorization to "delete cluster".
- **Nonce stripping:** `nonce` is in the signed payload. A tampered ADO with a different nonce is invalid.
- **Expiry extension:** `expires_at` is in the signed payload. An attacker cannot extend validity.
- **Cross-org constraint mutation:** `propagated_constraints` is in the signed payload.

### What the signature chain prevents

- **Authority impersonation:** Each signature in the chain is independently verifiable with the public key embedded in that chain entry.
- **Chain reordering:** Each signature covers all prior signatures; reordering invalidates all signatures after the reordered entry.

---

## 7. Implementation Notes

### Python reference

The reference implementation uses:

```python
import json
json.dumps(payload, sort_keys=True, separators=(',', ':'))
```

Note: Python's `json.dumps` uses `(', ', ': ')` separators by default (with spaces). The `separators=(',', ':')` argument is **required** — the reference implementation enforces compact form (CJ-2) since v0.4.0.

### JavaScript

```javascript
JSON.stringify(obj, Object.keys(obj).sort(), 0)
// Note: does not recursively sort nested objects — use a recursive implementation
```

### Go

```go
import "encoding/json"
// encoding/json does not sort keys; use a custom marshaler or github.com/tent/canonical-json-go
```

### Rust

```rust
// Use serde_json with BTreeMap (which sorts keys) instead of HashMap
use std::collections::BTreeMap;
```

---

## 8. Test Vectors

### Proposal hash test vector

Input:
```json
{
  "decision_id":   "550e8400-e29b-41d4-a716-446655440000",
  "decision_type": "remediation",
  "proposed_by":   "soc-agent/v1",
  "description":   "Isolate host dev-42 due to anomalous outbound traffic",
  "target":        "host:dev-42",
  "reversibility": true,
  "blast_radius":  "isolated",
  "expires_at":    null
}
```

Canonical form (CJ-2 compliant, no whitespace):

```
{"blast_radius":"isolated","decision_id":"550e8400-e29b-41d4-a716-446655440000","decision_type":"remediation","description":"Isolate host dev-42 due to anomalous outbound traffic","expires_at":null,"proposed_by":"soc-agent/v1","reversibility":true,"target":"host:dev-42"}
```

Expected SHA-256:

```
# TODO: compute reference value with conformance test suite (Phase 4)
# python3 -c "import json,hashlib; data={...}; print(hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest())"
```

> Computed reference hash values will be added once the conformance test suite enforces the separator convention across all language implementations.
