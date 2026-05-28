"""
tests/replay/test_replay.py

Shani Replay Attack Test Suite — MUST FAIL / MUST PASS.

Verifies that the Shani implementation correctly prevents replay attacks.
Each test validates a specific replay attack vector against the specification.

Test cases:
    1. nonce_replay              — same ADO nonce used twice (SPEC §5.4)
    2. expired_ado_resubmission  — expired ADO presented for execution (SPEC §5.3)
    3. time_window_replay        — ADO outside its valid time window (SPEC §5.3)
    4. valid_sig_consumed_nonce  — valid signature + consumed nonce → rejected (SPEC §5.4)
    5. cross_session_replay      — replay blocked across evaluator instances (SPEC §5.4)

Internal functions are prefixed with `_test_` and take a `ConformanceSuite` argument.
Pytest-compatible wrappers (no arguments) call these and assert no failures.
"""
from __future__ import annotations

import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_CONFORMANCE = os.path.normpath(os.path.join(_HERE, "../conformance"))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, _HERE)
sys.path.insert(0, _CONFORMANCE)

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t, importlib.util as _iu, pathlib as _pl
    _spec = _iu.spec_from_file_location(
        "_compat",
        str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py"),
    )
    _mod = _iu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _shim = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_shim, _k, getattr(_mod, _k))
    sys.modules["pydantic"] = _shim

import warnings
warnings.filterwarnings("ignore")

from shani.security.replay_store import (
    NonceAlreadyConsumed,
    InMemoryNonceStore,
    FileNonceStore,
)

# Fix: explicitly load from tests/conformance/
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../conformance"))

from framework import ConformanceSuite  # tests/conformance/framework.py
from fixtures import (  # tests/conformance/fixtures.py
    make_evaluator,
    make_proposal,
    make_valid_ado,
    make_expired_ado,
    past,
    future,
)


# ---------------------------------------------------------------------------
# 1. Nonce Replay — SPEC §5.4
# ---------------------------------------------------------------------------


def _test_nonce_replay(suite: ConformanceSuite) -> None:
    suite._section("1. Nonce Replay — Same ADO nonce used twice (SPEC §5.4)")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = make_valid_ado(ev, proposal)

    # Baseline: verify_binding() must succeed before nonce is consumed
    suite.must_pass(
        "nonce_replay:verify_binding_before_consume",
        condition=ev.verify_binding(ado, proposal),
        description="valid ADO: verify_binding() returns True before nonce consumed",
        spec_ref="SPEC §5.4",
    )

    # First register_executed() must succeed
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
        first_ok = True
    except Exception as exc:
        suite.must_pass(
            "nonce_replay:first_registration",
            condition=False,
            description="first register_executed() must succeed",
            detail=str(exc),
            spec_ref="SPEC §5.4",
        )
        return

    suite.must_pass(
        "nonce_replay:first_registration",
        condition=first_ok,
        description="first register_executed() succeeds",
        spec_ref="SPEC §5.4",
    )

    # Nonce store must record the nonce as consumed
    suite.must_fail(
        "nonce_replay:nonce_store_reports_consumed",
        condition=ev._nonce_store.is_consumed(ado.nonce),
        description="nonce store records nonce as consumed after register_executed()",
        spec_ref="SPEC §5.4",
    )

    # verify_binding() must return False after nonce is consumed
    suite.must_fail(
        "nonce_replay:verify_binding_post_consume",
        condition=not ev.verify_binding(ado, proposal),
        description="verify_binding() returns False after nonce consumed",
        spec_ref="SPEC §5.4",
    )

    # Second register_executed() must raise NonceAlreadyConsumed
    replay_blocked = False
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
    except NonceAlreadyConsumed:
        replay_blocked = True
    except Exception:
        replay_blocked = False

    suite.must_fail(
        "nonce_replay:second_registration_blocked",
        condition=replay_blocked,
        description="second register_executed() raises NonceAlreadyConsumed",
        spec_ref="SPEC §5.4",
    )

    # Exception message must provide audit context (not empty)
    try:
        ev.register_executed(ado, agent_id="agent/attacker")
    except NonceAlreadyConsumed as exc:
        suite.must_fail(
            "nonce_replay:exception_provides_context",
            condition=len(str(exc)) > 20,
            description="NonceAlreadyConsumed exception provides context for audit",
            detail=str(exc)[:80],
            spec_ref="SPEC §5.4",
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 2. Expired ADO Resubmission — SPEC §5.3
# ---------------------------------------------------------------------------


def _test_expired_ado_resubmission(suite: ConformanceSuite) -> None:
    suite._section("2. Expired ADO Resubmission (SPEC §5.3)")

    ev = make_evaluator()
    proposal = make_proposal()
    valid_ado = make_valid_ado(ev, proposal)

    # Baseline: fresh ADO must not be expired
    suite.must_pass(
        "expired_resubmit:valid_ado_not_expired",
        condition=not valid_ado.is_expired(),
        description="baseline: valid fresh ADO is not expired",
        spec_ref="SPEC §5.3",
    )
    suite.must_pass(
        "expired_resubmit:valid_ado_verify",
        condition=ev.verify_binding(valid_ado, proposal),
        description="baseline: valid fresh ADO passes verify_binding()",
        spec_ref="SPEC §5.3",
    )

    # Expired ADO resubmission must be rejected on every check
    expired_ado = make_expired_ado(ev)

    suite.must_fail(
        "expired_resubmit:is_expired",
        condition=expired_ado.is_expired(),
        description="expired ADO: is_expired() returns True",
        detail=f"expires_at={expired_ado.expires_at.isoformat()}",
        spec_ref="SPEC §5.3",
    )
    suite.must_fail(
        "expired_resubmit:verify_binding",
        condition=not ev.verify_binding(expired_ado, proposal),
        description="expired ADO: verify_binding() returns False",
        spec_ref="SPEC §5.3",
    )
    suite.must_fail(
        "expired_resubmit:time_remaining_zero",
        condition=expired_ado.time_remaining_seconds() == 0.0,
        description="expired ADO: time_remaining_seconds() == 0.0",
        spec_ref="SPEC §5.3",
    )


# ---------------------------------------------------------------------------
# 3. Time Window Replay — SPEC §5.3
# ---------------------------------------------------------------------------


def _test_time_window_replay(suite: ConformanceSuite) -> None:
    suite._section("3. Time Window Replay — ADO outside valid time window (SPEC §5.3)")

    ev = make_evaluator()
    proposal = make_proposal()
    valid_ado = make_valid_ado(ev, proposal)

    # ADO within valid time window must be accepted
    remaining = valid_ado.time_remaining_seconds()
    suite.must_pass(
        "time_window:within_window",
        condition=remaining > 0,
        description="ADO within valid time window: time_remaining_seconds() > 0",
        detail=f"time remaining: {remaining:.1f}s",
        spec_ref="SPEC §5.3",
    )
    suite.must_pass(
        "time_window:within_window_verify",
        condition=ev.verify_binding(valid_ado, proposal),
        description="ADO within valid time window: verify_binding() returns True",
        spec_ref="SPEC §5.3",
    )

    # ADO captured and replayed 1 hour later (expires_at in the past)
    old_ado = valid_ado.model_copy(update={
        "issued_at":  past(seconds=3600),   # issued 1 hour ago
        "expires_at": past(seconds=3000),   # expired 50 minutes ago
    })

    suite.must_fail(
        "time_window:very_old_expired",
        condition=old_ado.is_expired(),
        description="very old ADO (captured 1 hour ago): is_expired() returns True",
        spec_ref="SPEC §5.3",
    )
    suite.must_fail(
        "time_window:very_old_verify_blocked",
        condition=not ev.verify_binding(old_ado, proposal),
        description="very old ADO: verify_binding() returns False",
        spec_ref="SPEC §5.3",
    )

    # ADO that expired just 1 second ago
    just_expired = valid_ado.model_copy(update={
        "issued_at":  past(seconds=65),
        "expires_at": past(seconds=1),
    })

    suite.must_fail(
        "time_window:just_expired",
        condition=just_expired.is_expired(),
        description="ADO that just expired (1s ago): is_expired() returns True",
        spec_ref="SPEC §5.3",
    )
    suite.must_fail(
        "time_window:just_expired_remaining_zero",
        condition=just_expired.time_remaining_seconds() == 0.0,
        description="ADO that just expired: time_remaining_seconds() == 0.0",
        spec_ref="SPEC §5.3",
    )


# ---------------------------------------------------------------------------
# 4. Valid Signature but Consumed Nonce — SPEC §5.4
# ---------------------------------------------------------------------------


def _test_valid_sig_consumed_nonce(suite: ConformanceSuite) -> None:
    suite._section("4. Valid Signature but Consumed Nonce (SPEC §5.4)")

    ev = make_evaluator()
    proposal = make_proposal()
    ado = make_valid_ado(ev, proposal)

    # Establish that the ADO has a valid cryptographic binding before consumption
    suite.must_pass(
        "valid_sig_consumed:signature_valid_before",
        condition=ev.verify_binding(ado, proposal),
        description="ADO: verify_binding() passes before nonce consumed",
        spec_ref="SPEC §5.4",
    )

    # Consume the nonce (first legitimate execution)
    try:
        ev.register_executed(ado, agent_id="agent/conformance")
    except Exception as exc:
        suite.must_pass(
            "valid_sig_consumed:consume_step",
            condition=False,
            description="consume step: register_executed() must succeed",
            detail=str(exc),
            spec_ref="SPEC §5.4",
        )
        return

    # The replay guard must block verify_binding() even though the signature is
    # still cryptographically valid — nonce consumption takes precedence
    suite.must_fail(
        "valid_sig_consumed:replay_blocked_after",
        condition=not ev.verify_binding(ado, proposal),
        description="replay guard overrides valid signature: verify_binding() returns False",
        detail="signature is cryptographically valid but nonce is consumed",
        spec_ref="SPEC §5.4",
    )

    # Consumed nonce must be permanently recorded in the store
    suite.must_fail(
        "valid_sig_consumed:nonce_in_store",
        condition=ev._nonce_store.is_consumed(ado.nonce),
        description="consumed nonce is permanently recorded in nonce store",
        spec_ref="SPEC §5.4",
    )

    # Audit trail must be retrievable for incident response
    record = ev._nonce_store.get_record(ado.nonce)
    has_audit_trail = (
        record is not None
        and "decision_id" in record
        and "consumed_at" in record
    )
    suite.must_fail(
        "valid_sig_consumed:audit_trail_exists",
        condition=has_audit_trail,
        description="nonce store retains audit record with decision_id and consumed_at",
        detail=str(record),
        spec_ref="SPEC §5.4",
    )


# ---------------------------------------------------------------------------
# 5. Cross-Session Replay — SPEC §5.4
# ---------------------------------------------------------------------------


def _test_cross_session_replay(suite: ConformanceSuite) -> None:
    suite._section("5. Cross-Session Replay (SPEC §5.4)")

    # --- 5a: Shared InMemoryNonceStore blocks replay across two evaluators ---
    suite._section("  5a. Shared in-memory store")

    shared_store = InMemoryNonceStore()
    ev1 = make_evaluator(nonce_store=shared_store)
    ev2 = make_evaluator(nonce_store=shared_store)

    proposal = make_proposal()
    ado = make_valid_ado(ev1, proposal)

    # Session 1: first execution succeeds
    try:
        ev1.register_executed(ado, agent_id="agent/conformance")
        session1_ok = True
    except Exception as exc:
        suite.must_pass(
            "cross_session:shared_store_session1",
            condition=False,
            description="session 1: register_executed() succeeds with shared store",
            detail=str(exc),
            spec_ref="SPEC §5.4",
        )
        return

    suite.must_pass(
        "cross_session:shared_store_session1",
        condition=session1_ok,
        description="session 1: register_executed() succeeds with shared store",
        spec_ref="SPEC §5.4",
    )

    # Session 2 with the SAME shared store: replay must be blocked
    replay_blocked = False
    try:
        ev2.register_executed(ado, agent_id="agent/conformance")
    except NonceAlreadyConsumed:
        replay_blocked = True
    except Exception:
        replay_blocked = False

    suite.must_fail(
        "cross_session:shared_store_replay_blocked",
        condition=replay_blocked,
        description="session 2 (shared store): register_executed() raises NonceAlreadyConsumed",
        spec_ref="SPEC §5.4",
    )

    # verify_binding() in session 2 must also return False
    suite.must_fail(
        "cross_session:shared_store_verify_blocked",
        condition=not ev2.verify_binding(ado, proposal),
        description="session 2 (shared store): verify_binding() returns False",
        spec_ref="SPEC §5.4",
    )

    # --- 5b: FileNonceStore survives process-restart simulation ---
    suite._section("  5b. File-backed store survives reload")

    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = os.path.join(tmpdir, "nonces.jsonl")

        # Process 1: create FileNonceStore, issue and execute ADO
        store_p1 = FileNonceStore(store_path)
        ev_p1 = make_evaluator(nonce_store=store_p1)
        proposal2 = make_proposal()
        ado2 = make_valid_ado(ev_p1, proposal2)

        try:
            ev_p1.register_executed(ado2, agent_id="agent/conformance")
            process1_ok = True
        except Exception as exc:
            suite.must_pass(
                "cross_session:file_store_process1",
                condition=False,
                description="process 1: register_executed() with FileNonceStore succeeds",
                detail=str(exc),
                spec_ref="SPEC §5.4",
            )
            return

        suite.must_pass(
            "cross_session:file_store_process1",
            condition=process1_ok,
            description="process 1: register_executed() with FileNonceStore succeeds",
            spec_ref="SPEC §5.4",
        )

        # Process 2: reload FileNonceStore from the same file — nonce must persist
        store_p2 = FileNonceStore(store_path)

        suite.must_fail(
            "cross_session:file_store_nonce_persisted",
            condition=store_p2.is_consumed(ado2.nonce),
            description="FileNonceStore reload: consumed nonce persists across sessions",
            spec_ref="SPEC §5.4",
        )

        # Process 2 must block replay via its reloaded store
        ev_p2 = make_evaluator(nonce_store=store_p2)
        replay_blocked_p2 = False
        try:
            ev_p2.register_executed(ado2, agent_id="agent/conformance")
        except NonceAlreadyConsumed:
            replay_blocked_p2 = True
        except Exception:
            replay_blocked_p2 = False

        suite.must_fail(
            "cross_session:file_store_cross_process_blocked",
            condition=replay_blocked_p2,
            description="FileNonceStore: cross-process replay blocked after store reload",
            spec_ref="SPEC §5.4",
        )


# ---------------------------------------------------------------------------
# Entry point (standalone + pytest)
# ---------------------------------------------------------------------------


def run() -> ConformanceSuite:
    suite = ConformanceSuite("Replay Attack Test Suite")

    _test_nonce_replay(suite)
    _test_expired_ado_resubmission(suite)
    _test_time_window_replay(suite)
    _test_valid_sig_consumed_nonce(suite)
    _test_cross_session_replay(suite)

    return suite


# ---------------------------------------------------------------------------
# pytest-compatible wrappers (no parameters — pytest discovers and runs these)
# ---------------------------------------------------------------------------


def test_nonce_replay() -> None:
    suite = ConformanceSuite("replay:nonce_replay")
    _test_nonce_replay(suite)
    assert suite.report.failed_count == 0, (
        f"{suite.report.failed_count} test(s) failed: "
        + ", ".join(r.test_id for r in suite.report.failures)
    )


def test_expired_ado_resubmission() -> None:
    suite = ConformanceSuite("replay:expired_ado_resubmission")
    _test_expired_ado_resubmission(suite)
    assert suite.report.failed_count == 0, (
        f"{suite.report.failed_count} test(s) failed: "
        + ", ".join(r.test_id for r in suite.report.failures)
    )


def test_time_window_replay() -> None:
    suite = ConformanceSuite("replay:time_window_replay")
    _test_time_window_replay(suite)
    assert suite.report.failed_count == 0, (
        f"{suite.report.failed_count} test(s) failed: "
        + ", ".join(r.test_id for r in suite.report.failures)
    )


def test_valid_sig_consumed_nonce() -> None:
    suite = ConformanceSuite("replay:valid_sig_consumed_nonce")
    _test_valid_sig_consumed_nonce(suite)
    assert suite.report.failed_count == 0, (
        f"{suite.report.failed_count} test(s) failed: "
        + ", ".join(r.test_id for r in suite.report.failures)
    )


def test_cross_session_replay() -> None:
    suite = ConformanceSuite("replay:cross_session_replay")
    _test_cross_session_replay(suite)
    assert suite.report.failed_count == 0, (
        f"{suite.report.failed_count} test(s) failed: "
        + ", ".join(r.test_id for r in suite.report.failures)
    )


if __name__ == "__main__":
    print("=" * 60)
    print("  Shani Replay Attack Test Suite")
    print("=" * 60)

    s = run()
    s.report.print_summary()
    s.report.assert_all_passed()
