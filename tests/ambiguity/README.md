# tests/ambiguity — Ambiguity Escalation Test Suite

Tests for T15 (Ambiguity Escalation) and related boundary ambiguity cases.

## Background

`spec/threat-model.md §T15` describes Ambiguity Escalation:

> An agent deliberately constructs proposals with ambiguous scope or intent to force
> `AMBIGUOUS` PostureEngine results, triggering `PostureRefinementRequest` responses
> instead of firm denials. By accumulating refinement requests, the agent maps the
> Posture boundary and finds the narrowest path to approval.

This suite ensures that:
1. Ambiguous cases are handled consistently and deterministically across implementations.
2. `PostureRefinementRequest` does not leak full posture evaluation details.
3. Every structural constraint violation produces `REJECT` (not `AMBIGUOUS`).
4. Type coercion, Unicode, and timestamp handling cannot be exploited to create
   unintended `PASS` outcomes.

## Test Files

| File | Coverage |
|---|---|
| `test_boundary_conditions.py` | Blast radius, evidence count, target scope, confidence, and `expires_at` at exact boundary values |
| `test_field_defaults.py` | Default behavior of optional fields (`DecisionScope`, `EvidenceItem`, `DelegationRules`, posture history) |
| `test_type_coercion.py` | Enum value coercion (`BlastRadius`, `DecisionType`), confidence float bounds, boolean fields |
| `test_dsal_escalation.py` | T15 AMBIGUOUS trigger, T3 `requested_dsal` absence, DSALCalculator cap and modifiers, T4 delegation invariant |
| `test_timestamp_timezone.py` | Timezone-aware vs naive datetimes, `is_expired()` boundary, `canonical_hash` stability |
| `test_unicode_encoding.py` | Multibyte Unicode in proposal fields, homoglyph target bypass prevention, encoding stability |
| `test_permission_boundaries.py` | Reversibility boundary, agent D-SAL boundary, OrgPolicy override, structural vs semantic violations |

## Running

```bash
# Run the full ambiguity suite
pytest tests/ambiguity/ -v

# Run a single file
pytest tests/ambiguity/test_dsal_escalation.py -v

# Run with coverage
pytest tests/ambiguity/ --cov=shani --cov-report=term-missing
```

## CI Integration

The suite is automatically discovered by `pytest` via `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
```

All tests in `tests/ambiguity/` run as part of `pytest` in the CI `test` job
(`Run all test suites` step in `.github/workflows/ci.yml`).

## Known Open Issues

- T15 rate limiting is RECOMMENDED (not yet normative). The suite verifies logging
  is not prevented, but does not test rate-limit enforcement.
- Cross-implementation consistency requires running the suite against multiple Shani
  implementations with the same test vectors (see `spec/interoperability/`).
