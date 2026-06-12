"""
tests/replay/

Shani Replay Attack Test Suite.

This package verifies that a Shani implementation correctly prevents
replay attacks as defined in the Shani specification.

Tests are split into two categories:

    MUST_FAIL  — the implementation MUST reject / deny the replay attempt.
    MUST_PASS  — the implementation MUST accept valid, first-time ADOs.

Test cases:
    1. nonce_replay              — same ADO nonce used twice (SPEC §5.4)
    2. expired_ado_resubmission  — expired ADO presented for execution (SPEC §5.3)
    3. time_window_replay        — ADO outside its valid time window (SPEC §5.3)
    4. valid_sig_consumed_nonce  — valid signature + consumed nonce → rejected (SPEC §5.4)
    5. cross_session_replay      — replay blocked across evaluator instances (SPEC §5.4)

Entry points:
    python tests/replay/runner.py                  # run all, print report
    python tests/replay/runner.py --json out.json  # JSON report
    python tests/replay/test_replay.py             # run directly
    pytest tests/replay/                           # run via pytest
"""
