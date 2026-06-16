"""
tests/ambiguity/test_unicode_encoding.py

Tests for Unicode and character encoding handling.

Ambiguity risk: implementations that normalize, truncate, or misinterpret
Unicode in proposal fields may create security gaps.

Covers:
- target with multi-byte Unicode characters
- homoglyph target bypass prevention
- description with Unicode
- evidence content with Unicode
- canonical_hash includes Unicode content verbatim
- Empty string fields rejected (min_length enforcement)
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

from datetime import datetime, timedelta, timezone

from shani.schemas.decision import EvidenceItem
from shani.schemas.posture import PostureOutcome

from framework import ConformanceSuite
from ambiguity_fixtures import make_proposal, make_posture, evaluate_posture, future


# ---------------------------------------------------------------------------
# 1. Unicode in target field
# ---------------------------------------------------------------------------


def test_unicode_target_accepted(suite: ConformanceSuite) -> None:
    """target with multibyte Unicode must be accepted by the schema."""
    suite._section("1. Unicode target accepted")
    unicode_targets = [
        "host:サーバー-01",
        "host:서버-dev",
        "host:dev-élève",
    ]
    for target in unicode_targets:
        proposal = make_proposal(target=target)
        suite.must_pass(
            f"unicode:target_{hash(target) % 10000}",
            proposal.target == target,
            f"target={target!r} stored verbatim",
            f"got {proposal.target!r}",
        )


def test_unicode_target_regex_match(suite: ConformanceSuite) -> None:
    """PostureEngine must treat Unicode targets consistently with regex matching."""
    suite._section("1b. Unicode target vs regex pattern")
    posture_dev = make_posture(target_scope=r"host:dev-.*")

    proposal_ascii = make_proposal(target="host:dev-01")
    outcome_ascii, _ = evaluate_posture(proposal_ascii, posture_dev)
    suite.must_pass(
        "unicode:ascii_target_passes",
        outcome_ascii == PostureOutcome.PASS,
        "ASCII target matching regex → PASS",
        f"got {outcome_ascii}",
    )

    proposal_unicode = make_proposal(target="host:dev-élève")
    outcome_unicode, _ = evaluate_posture(proposal_unicode, posture_dev)
    suite.must_pass(
        "unicode:unicode_target_passes",
        outcome_unicode == PostureOutcome.PASS,
        "Unicode target matching regex → PASS",
        f"got {outcome_unicode}",
    )


def test_homoglyph_target_does_not_bypass_pattern(suite: ConformanceSuite) -> None:
    """Homoglyphs in target must not cause a false match against a production pattern."""
    suite._section("1c. Homoglyph target does not bypass pattern")
    posture = make_posture(target_scope=r"^host:prod-.*")
    # Cyrillic 'р' (U+0440) looks like Latin 'p' — 'host:рrod-01'
    homoglyph_target = "host:рrod-01"
    proposal = make_proposal(target=homoglyph_target)
    outcome, _ = evaluate_posture(proposal, posture)
    suite.must_fail(
        "unicode:homoglyph_no_bypass",
        outcome == PostureOutcome.REJECT,
        "homoglyph target does not match production pattern",
        f"got {outcome} for target={homoglyph_target!r}",
    )


# ---------------------------------------------------------------------------
# 2. Unicode in description field
# ---------------------------------------------------------------------------


def test_unicode_description_accepted(suite: ConformanceSuite) -> None:
    """description with Unicode characters must be accepted and stored verbatim."""
    suite._section("2. Unicode description accepted verbatim")
    desc = "システムの修復: ホスト dev-01 を隔離する"
    proposal = make_proposal(description=desc)
    suite.must_pass(
        "unicode:description_verbatim",
        proposal.description == desc,
        "Unicode description stored verbatim",
        f"got {proposal.description!r}",
    )


# ---------------------------------------------------------------------------
# 3. Unicode in evidence content
# ---------------------------------------------------------------------------


def test_unicode_evidence_content(suite: ConformanceSuite) -> None:
    """EvidenceItem.content with Unicode must be stored verbatim."""
    suite._section("3. Unicode evidence content")
    content = "CPU使用率99%: ホスト dev-01"
    item = EvidenceItem(source="sensor", content=content, confidence=0.9)
    suite.must_pass(
        "unicode:evidence_content_verbatim",
        item.content == content,
        "Unicode evidence content stored verbatim",
        f"got {item.content!r}",
    )


# ---------------------------------------------------------------------------
# 4. canonical_hash includes Unicode content verbatim
# ---------------------------------------------------------------------------


def test_canonical_hash_unicode_stability(suite: ConformanceSuite) -> None:
    """canonical_hash must be stable for proposals with Unicode fields."""
    suite._section("4. canonical_hash Unicode stability")
    proposal = make_proposal(
        target="host:dev-élève",
        description="Unicode proposal",
    )
    h1 = proposal.canonical_hash()
    h2 = proposal.canonical_hash()
    suite.must_pass(
        "unicode:hash_stable",
        h1 == h2,
        "canonical_hash stable for Unicode content",
        f"hashes differ: {h1} vs {h2}",
    )


def test_canonical_hash_unicode_vs_ascii_differs(suite: ConformanceSuite) -> None:
    """canonical_hash of a Unicode target must differ from its ASCII near-equivalent."""
    suite._section("4b. canonical_hash Unicode vs ASCII differs")
    expires = future(300)
    p_ascii = make_proposal(target="host:dev-01", expires_at=expires)
    p_unicode = make_proposal(target="host:dev-øl", expires_at=expires)
    suite.must_pass(
        "unicode:hash_differs_unicode_vs_ascii",
        p_ascii.canonical_hash() != p_unicode.canonical_hash(),
        "Unicode target produces different hash than ASCII near-equivalent",
    )


# ---------------------------------------------------------------------------
# 5. Empty string fields rejected (min_length enforcement)
# ---------------------------------------------------------------------------


def test_empty_target_rejected(suite: ConformanceSuite) -> None:
    """target='' must be rejected (min_length=1)."""
    suite._section("5. Empty target rejected")
    raised = False
    try:
        make_proposal(target="")
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "unicode:empty_target_rejected",
        raised,
        "empty target rejected by schema",
    )


def test_empty_description_rejected(suite: ConformanceSuite) -> None:
    """description='' must be rejected (min_length=1)."""
    suite._section("5b. Empty description rejected")
    raised = False
    try:
        make_proposal(description="")
    except (ValueError, Exception):
        raised = True
    suite.must_fail(
        "unicode:empty_description_rejected",
        raised,
        "empty description rejected by schema",
    )
