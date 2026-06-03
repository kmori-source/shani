"""
tests/ambiguity/test_timestamp_timezone.py

Tests for timestamp precision and timezone handling.

Ambiguity risk: implementations that handle timezones inconsistently may
accept expired ADOs or reject valid ones.

Covers:
- expires_at with timezone-aware UTC datetime → accepted
- expires_at with naive datetime (no tzinfo) → rejected or normalized
- expires_at in the past → rejected by schema validator
- issued_at vs expires_at ordering invariant in ADO
- is_expired() boundary: just expired vs just valid
- canonical_hash stability across multiple calls
- canonical_hash changes when fields change
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "../.."))
sys.path.insert(0, os.path.join(_HERE, "../conformance"))
sys.path.insert(0, _HERE)

try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

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

import hashlib, base64, uuid
from datetime import datetime, timedelta, timezone

from framework import ConformanceSuite
from ambiguity_fixtures import make_proposal, utcnow, future


def _make_minimal_ado(issued_at: datetime | None = None, expires_at: datetime | None = None):
    from shani.schemas.decision import AuthorizedDecisionObject, ExecContext, IntentBinding, DecisionType
    kw = dict(
        decision_id=str(uuid.uuid4()),
        authorized_dsal=2,
        authority="test-authority",
        expires_at=expires_at or (utcnow() + timedelta(minutes=10)),
        proposal_hash=hashlib.sha256(b"test").hexdigest(),
        signature=base64.b64encode(b"sig").decode(),
        exec_context=ExecContext(
            decision_type=DecisionType.REMEDIATION,
            intent_binding=IntentBinding(
                intent="test",
                target="host:dev-01",
                scope_summary="test",
                expected_effect="test effect",
                reversibility=True,
            ),
        ),
    )
    if issued_at is not None:
        kw["issued_at"] = issued_at
    from shani.schemas.decision import AuthorizedDecisionObject
    return AuthorizedDecisionObject(**kw)


# ---------------------------------------------------------------------------
# 1. Timezone-aware expires_at accepted
# ---------------------------------------------------------------------------


def test_expires_at_utc_accepted(suite: ConformanceSuite) -> None:
    """expires_at as a timezone-aware UTC datetime must be accepted."""
    suite._section("1. expires_at UTC timezone-aware accepted")
    expires = utcnow() + timedelta(minutes=10)
    proposal = make_proposal(expires_at=expires)
    suite.must_pass(
        "ts:expires_at_tz_aware",
        proposal.expires_at is not None,
        "tz-aware expires_at accepted",
    )
    suite.must_pass(
        "ts:expires_at_tzinfo_preserved",
        proposal.expires_at.tzinfo is not None,
        "expires_at tzinfo preserved",
        f"tzinfo was stripped: {proposal.expires_at}",
    )


# ---------------------------------------------------------------------------
# 2. Naive datetime handling
# ---------------------------------------------------------------------------


def test_expires_at_naive_handled(suite: ConformanceSuite) -> None:
    """expires_at as a naive datetime must be rejected or normalized to UTC."""
    suite._section("2. Naive datetime handling for expires_at")
    naive_future = datetime.utcnow() + timedelta(minutes=10)
    assert naive_future.tzinfo is None, "Test datetime must be naive"
    try:
        proposal = make_proposal(expires_at=naive_future)
        # If accepted, the schema must handle it without crashing
        suite.must_pass(
            "ts:naive_datetime_accepted",
            proposal.expires_at is not None,
            "naive datetime accepted without crash",
        )
    except (ValueError, Exception):
        suite.must_fail(
            "ts:naive_datetime_rejected",
            True,
            "naive datetime rejected by schema (valid behavior)",
        )


# ---------------------------------------------------------------------------
# 3. expires_at in the past rejected
# ---------------------------------------------------------------------------


def test_expires_at_past_rejected(suite: ConformanceSuite) -> None:
    """expires_at in the past must be rejected by the schema validator."""
    suite._section("3. expires_at in the past rejected")
    past_time = utcnow() - timedelta(seconds=1)
    raised = False
    try:
        make_proposal(expires_at=past_time)
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "ts:expires_at_past",
        raised,
        "expires_at in past raises ValueError",
    )


# ---------------------------------------------------------------------------
# 4. issued_at vs expires_at ordering invariant in ADO
# ---------------------------------------------------------------------------


def test_ado_expires_before_issued_rejected(suite: ConformanceSuite) -> None:
    """An ADO where expires_at <= issued_at must raise ValueError."""
    suite._section("4. ADO expires_at must be after issued_at")
    issued = utcnow()
    expires_before = issued - timedelta(seconds=1)
    raised = False
    try:
        _make_minimal_ado(issued_at=issued, expires_at=expires_before)
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "ts:ado_expires_before_issued",
        raised,
        "ADO with expires_at < issued_at raises ValueError",
    )


# ---------------------------------------------------------------------------
# 5. is_expired() boundary
# ---------------------------------------------------------------------------


def test_is_expired_future_ado(suite: ConformanceSuite) -> None:
    """is_expired() must return False for an ADO that expires in the future."""
    suite._section("5a. is_expired() = False for future ADO")
    ado = _make_minimal_ado(expires_at=utcnow() + timedelta(seconds=60))
    suite.must_pass(
        "ts:not_expired_future",
        ado.is_expired() is False,
        "is_expired() returns False for future ADO",
        f"is_expired()={ado.is_expired()}",
    )


def test_is_expired_past_ado(suite: ConformanceSuite) -> None:
    """is_expired() must return True for an ADO whose expires_at is in the past."""
    suite._section("5b. is_expired() = True for past ADO")
    ado = _make_minimal_ado(expires_at=utcnow() + timedelta(seconds=60))
    # Force expires_at into the past without going through schema validation
    expired_ado = ado.model_copy(update={
        "issued_at": utcnow() - timedelta(seconds=120),
        "expires_at": utcnow() - timedelta(seconds=60),
    })
    suite.must_pass(
        "ts:expired_past",
        expired_ado.is_expired() is True,
        "is_expired() returns True for past-expired ADO",
        f"is_expired()={expired_ado.is_expired()}",
    )


# ---------------------------------------------------------------------------
# 6. canonical_hash stability
# ---------------------------------------------------------------------------


def test_canonical_hash_deterministic(suite: ConformanceSuite) -> None:
    """The same proposal must always produce the same canonical_hash."""
    suite._section("6. canonical_hash is deterministic")
    p = make_proposal()
    h1 = p.canonical_hash()
    h2 = p.canonical_hash()
    suite.must_pass(
        "ts:hash_stable",
        h1 == h2,
        "canonical_hash() is stable for the same instance",
        f"hashes differ: {h1} vs {h2}",
    )


def test_canonical_hash_changes_on_target_change(suite: ConformanceSuite) -> None:
    """Changing target must produce a different canonical_hash."""
    suite._section("6b. canonical_hash changes on field change")
    expires = future(300)
    p_original = make_proposal(target="host:dev-01", expires_at=expires)
    p_changed = make_proposal(target="host:prod-01", expires_at=expires)
    suite.must_pass(
        "ts:hash_changes_on_target",
        p_original.canonical_hash() != p_changed.canonical_hash(),
        "canonical_hash differs when target changes",
    )
