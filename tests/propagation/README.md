# tests/propagation/

Dedicated test suite for `propagated_constraints` propagation behaviour.

## Motivation

`propagated_constraints` is the mechanism (ADO v5.1 / SPEC §8.8–§8.9) that
prevents **Cross-Organizational Chain Dilution**: when an ADO crosses org
boundaries, the originating principal's `UserPosture` constraints are embedded
as a signed, cryptographically immutable field and validated at every downstream
hop.  Without this enforcement, constraints declared by Org A can silently
disappear by the time the action reaches Org D in a four-org supply chain.

See [RFC-0002](../../rfcs/RFC-0002-propagated-constraints.md) for the full
design rationale.

## Structure

```
tests/propagation/
├── __init__.py
├── conftest.py                      # pytest fixtures (ConformanceSuite)
├── fixtures.py                      # shared factories (evaluators, ADOs, proposals)
├── test_constraint_propagation.py   # inheritance, monotonicity, tamper detection
├── test_missing_constraints.py      # MUST FAIL: empty/unknown/malformed constraints
├── test_cross_org.py                # cross-org supply chain scenarios
├── test_delegation_chain.py         # multi-hop delegation chain tests
└── README.md                        # this file
```

## Test files

### `test_constraint_propagation.py`

Verifies correct propagation behaviour on the happy path:

| Test | Spec ref |
|---|---|
| Parent propagated_constraints inherited by child ADO | SPEC §8.8 |
| Child proposal outside propagated scope → PostureRefinementRequest | SPEC §8.8 |
| Tampered propagated_constraints → verify_binding() False | SPEC §4.5 |
| Constraint narrowing (child may add, not remove) | RFC-0002 |
| UserPosture fields serialised to propagated_constraints strings | SPEC §8.8 |

### `test_missing_constraints.py`

MUST FAIL suite — cases the implementation must correctly reject:

| Test | Spec ref |
|---|---|
| Cross-org ADO with `propagated_constraints=[]` → AMBIGUOUS | SPEC §8.9 |
| `origin_org=None` does not trigger cross-org validation | SPEC §8.8 |
| Unknown vocabulary key → AMBIGUOUS (not PASS, fail-closed) | SPEC §8.8 |
| Malformed constraint string (no `:`) → AMBIGUOUS | SPEC §8.8 |
| Partial constraints: remaining known keys still enforced | SPEC §8.8 |

### `test_cross_org.py`

End-to-end cross-organisational scenarios:

| Test | Spec ref |
|---|---|
| Org A issues → Org B validates (supply chain happy path) | SPEC §8.8 |
| Org B proposal outside Org A's propagated scope → blocked | SPEC §8.8 |
| `cross_org_min_dsal` gates low-D-SAL cross-org ADOs | SPEC §8.8 |
| `origin_org` preserved unchanged through the chain | SPEC §8.8 |
| Irreversible proposal violates propagated `reversibility_required:true` | SPEC §8.8 |

### `test_delegation_chain.py`

Multi-hop delegation chain correctness:

| Test | Spec ref |
|---|---|
| Two-hop chain (Alpha→Beta→Gamma): constraints survive all hops | RFC-0002 |
| Three-hop chain (Alpha→Beta→Gamma→Delta): constraints end-to-end | RFC-0002 |
| Chain D-SAL ceiling: each hop cannot exceed parent's `max_child_dsal` | SPEC §6.2 |
| Constraint dilution prevention: stripped constraints still enforced | RFC-0002 |
| Chain depth limit: `max_depth=1` blocks further delegation | SPEC §6.2 |

## Running

```bash
# All propagation tests
pytest tests/propagation/ -v

# Single file
pytest tests/propagation/test_cross_org.py -v

# Standalone (no pytest required)
python tests/propagation/test_constraint_propagation.py
```

## Framework

Tests use the `ConformanceSuite` framework from `tests/conformance/framework.py`.
Each assertion is either:

- `suite.must_pass(id, condition, description)` — operation that MUST succeed
- `suite.must_fail(id, condition, description)` — operation that MUST be rejected

The `suite` pytest fixture automatically fails the test if any check is recorded
as failed.
