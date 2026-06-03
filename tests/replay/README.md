# Shani Replay Attack Test Suite

`tests/replay/` verifies Shani's replay attack prevention against the normative
specification (SPEC §5.3, §5.4), using MUST FAIL / MUST PASS conformance checks.

---

## Test overview

| # | Test ID | Category | Spec | Description |
|---|---------|----------|------|-------------|
| 1 | `nonce_replay` | MUST FAIL | §5.4 | Second use of the same ADO nonce is blocked |
| 2 | `expired_ado_resubmission` | MUST FAIL | §5.3 | Expired ADO resubmission is rejected |
| 3 | `time_window_replay` | MUST FAIL | §5.3 | ADO outside its validity window is rejected |
| 4 | `valid_sig_consumed_nonce` | MUST FAIL | §5.4 | Valid signature does not override a consumed nonce |
| 5 | `cross_session_replay` | MUST FAIL | §5.4 | Cross-session replay is blocked by a shared nonce store |

---

## Test categories

### MUST FAIL
Verifies that the implementation **correctly rejects** an operation.
`condition = True` → implementation rejected correctly (PASS)
`condition = False` → implementation did not reject (FAIL — security gap)

### MUST PASS
Verifies that a valid first-time ADO operation is **correctly accepted** (baseline).
`condition = True` → implementation accepted correctly (PASS)
`condition = False` → implementation rejected incorrectly (FAIL — over-blocking)

---

## Test cases

### 1. Nonce replay (SPEC §5.4)

Verifies that reusing the same ADO nonce is rejected.

- First `register_executed()` succeeds (MUST PASS)
- Second `register_executed()` raises `NonceAlreadyConsumed` (MUST FAIL)
- `verify_binding()` returns `False` after nonce is consumed (MUST FAIL)
- `_nonce_store.is_consumed(nonce)` returns `True` (MUST FAIL)
- Exception message includes audit context (MUST FAIL)

### 2. Expired ADO resubmission (SPEC §5.3)

Verifies that a re-presented expired ADO is rejected.

- Valid ADO: `is_expired() == False` (MUST PASS)
- Valid ADO: `verify_binding() == True` (MUST PASS)
- Expired ADO: `is_expired() == True` (MUST FAIL)
- Expired ADO: `verify_binding() == False` (MUST FAIL)
- Expired ADO: `time_remaining_seconds() == 0.0` (MUST FAIL)

### 3. Time window replay (SPEC §5.3)

Verifies that ADOs outside their validity window are rejected.

- ADO within window: `time_remaining_seconds() > 0` (MUST PASS)
- ADO issued and expired 1 hour ago: `is_expired() == True` (MUST FAIL)
- ADO expired 1 second ago: `is_expired() == True` (MUST FAIL)

### 4. Valid signature, consumed nonce (SPEC §5.4)

Verifies that replay prevention takes priority over cryptographic signature validity.

- Before nonce consumed: `verify_binding() == True` (MUST PASS)
- After nonce consumed: `verify_binding() == False` (MUST FAIL)
- Consumed nonce is permanently recorded in the store (MUST FAIL)
- `get_record()` returns audit trail (`decision_id`, `consumed_at`) (MUST FAIL)

### 5. Cross-session replay (SPEC §5.4)

Verifies that replay attacks across sessions are prevented by a shared nonce store.

**5a. Shared InMemoryNonceStore**
- Session 1 execution succeeds (MUST PASS)
- Session 2 replay (same store) raises `NonceAlreadyConsumed` (MUST FAIL)
- Session 2 `verify_binding()` returns `False` (MUST FAIL)

**5b. FileNonceStore reload (process restart simulation)**
- Process 1 execution succeeds (MUST PASS)
- Process 2 reloads store — nonce is still present (MUST FAIL)
- Process 2 replay is blocked (MUST FAIL)

---

## Running

```bash
# Standalone (recommended)
python tests/replay/runner.py

# JSON report
python tests/replay/runner.py --json report.json

# Direct
python tests/replay/test_replay.py

# pytest
pytest tests/replay/

# Full suite
pytest
```

---

## File structure

```
tests/replay/
├── __init__.py        # package description
├── test_replay.py     # test cases (pytest + standalone)
├── runner.py          # standalone runner
└── README.md          # this file
```

Reuses `tests/conformance/framework.py` and `tests/conformance/fixtures.py` directly
(no copy).

---

## Design principles

- **Append-only nonce store** — consumed nonces are never deleted
- **Replay guard > signature** — replay prevention is independent of signature verification
- **Persistent state** — `FileNonceStore` survives process restarts
- **MUST FAIL / MUST PASS distinction** — security gaps and over-blocking are tracked separately

---

## References

- [SPEC §5.3](../../spec/shani-v0.4.md) — ADO Expiry
- [SPEC §5.4](../../spec/shani-v0.4.md) — Replay Prevention
- [`shani/security/replay_store.py`](../../shani/security/replay_store.py) — implementation
- [`tests/conformance/test_must_fail.py`](../conformance/test_must_fail.py) — related conformance tests
