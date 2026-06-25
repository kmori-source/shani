"""
test_policy_engine.py - Regression tests for the Shani policy engine.

Written as standard pytest test functions so they are picked up by the
existing CI `test` job (pytest-based - see
00b_repo_branch_cicd_guide.md section 3.1). A previous draft of this file
used a custom `main()` script instead of `test_*` functions, which pytest
would have silently never discovered or run.

These tests pin down two things:
  1. The default policy reproduces every existing classification we already
     rely on (pip-audit D-SAL2, oss-crs patch heuristics).
  2. The "caller can only escalate, never de-escalate" security property
     actually holds.
"""
from pathlib import Path

import pytest

from shani.risk.blast_radius_policy import PolicyEngine, max_severity

POLICY_PATH = Path(__file__).parent.parent.parent / "blast_radius_policy" / "default.yaml"


@pytest.fixture(scope="module")
def engine() -> PolicyEngine:
    return PolicyEngine.from_yaml(POLICY_PATH)


# --- max_severity ordering ---------------------------------------------

def test_max_severity_orders_correctly():
    assert max_severity("limited", "isolated") == "limited"


def test_max_severity_handles_none():
    assert max_severity("limited", None) == "limited"


def test_max_severity_empty_defaults_to_isolated():
    assert max_severity() == "isolated"


# --- pip-audit D-SAL2 regression ----------------------------------------

def test_pip_audit_medium_maps_to_limited(engine):
    proposal = {
        "decision_type": "remediation",
        "proposed_by": "pip-audit-pipeline/v2",
        "evidence": [{"source": "pip-audit", "content": "...", "metadata": {"severity": "MEDIUM"}}],
    }
    result = engine.evaluate(proposal)
    assert result.blast_radius == "limited"


def test_pip_audit_high_maps_to_significant_not_critical(engine):
    proposal = {
        "decision_type": "remediation",
        "proposed_by": "pip-audit-pipeline/v2",
        "evidence": [{"source": "pip-audit", "content": "...", "metadata": {"severity": "HIGH"}}],
    }
    result = engine.evaluate(proposal)
    assert result.blast_radius == "significant"


def test_pip_audit_critical_maps_to_critical(engine):
    proposal = {
        "decision_type": "remediation",
        "proposed_by": "pip-audit-pipeline/v2",
        "evidence": [{"source": "pip-audit", "content": "...", "metadata": {"severity": "CRITICAL"}}],
    }
    result = engine.evaluate(proposal)
    assert result.blast_radius == "critical"


# --- oss-crs patch heuristic regression ----------------------------------

def _patch_proposal(metadata: dict) -> dict:
    return {
        "decision_type": "remediation",
        "proposed_by": "oss-crs-builder/crs-claude-code",
        "evidence": [{"source": "oss-crs-builder", "content": "...", "metadata": metadata}],
    }


def test_scoped_single_file_patch_maps_to_limited(engine):
    proposal = _patch_proposal(
        {
            "action_class": "patch_apply",
            "files_changed": ["parser.c"],
            "files_changed_count": 1,
            "total_lines_changed": 3,
        }
    )
    result = engine.evaluate(proposal)
    assert result.blast_radius == "limited"  # not the generic remediation default


def test_patch_touching_dockerfile_escalates_to_significant(engine):
    proposal = _patch_proposal(
        {
            "action_class": "patch_apply",
            "files_changed": ["Dockerfile"],
            "files_changed_count": 1,
            "total_lines_changed": 3,
        }
    )
    result = engine.evaluate(proposal)
    assert result.blast_radius == "significant"


def test_large_patch_escalates_to_significant(engine):
    proposal = _patch_proposal(
        {
            "action_class": "patch_apply",
            "files_changed": [f"file{i}.c" for i in range(8)],
            "files_changed_count": 8,
            "total_lines_changed": 320,
        }
    )
    result = engine.evaluate(proposal)
    assert result.blast_radius == "significant"


# --- decision_type defaults (no rule matches) -----------------------------

def test_generic_remediation_falls_back_to_significant_default(engine):
    proposal = {"decision_type": "remediation", "proposed_by": "some-agent/v1", "evidence": []}
    result = engine.evaluate(proposal)
    assert result.blast_radius == "significant"
    assert result.default_used is True


def test_data_access_default_is_isolated(engine):
    proposal = {"decision_type": "data_access", "proposed_by": "some-agent/v1", "evidence": []}
    result = engine.evaluate(proposal)
    assert result.blast_radius == "isolated"


# --- security property: caller can only escalate, never de-escalate ------

def test_caller_claiming_lower_than_policy_is_ignored(engine):
    proposal = {
        "decision_type": "remediation",
        "proposed_by": "pip-audit-pipeline/v2",
        "evidence": [{"source": "pip-audit", "content": "...", "metadata": {"severity": "MEDIUM"}}],
    }
    result = engine.evaluate(proposal)  # policy says "limited"
    assert result.effective("isolated") == "limited"


def test_caller_claiming_higher_than_policy_is_honored(engine):
    proposal = {
        "decision_type": "remediation",
        "proposed_by": "pip-audit-pipeline/v2",
        "evidence": [{"source": "pip-audit", "content": "...", "metadata": {"severity": "MEDIUM"}}],
    }
    result = engine.evaluate(proposal)
    assert result.effective("critical") == "critical"


def test_caller_claiming_nothing_leaves_policy_verdict_unchanged(engine):
    proposal = {
        "decision_type": "remediation",
        "proposed_by": "pip-audit-pipeline/v2",
        "evidence": [{"source": "pip-audit", "content": "...", "metadata": {"severity": "MEDIUM"}}],
    }
    result = engine.evaluate(proposal)
    assert result.effective(None) == "limited"


# --- policy file validation (fails fast on a malformed policy) -----------

def test_rejects_invalid_blast_radius_value():
    with pytest.raises(ValueError):
        PolicyEngine({"defaults": {}, "rules": [{"id": "r1", "match": {}, "blast_radius": "super-bad"}]})


def test_rejects_duplicate_rule_id():
    with pytest.raises(ValueError):
        PolicyEngine(
            {
                "defaults": {},
                "rules": [
                    {"id": "dup", "match": {}, "blast_radius": "limited"},
                    {"id": "dup", "match": {}, "blast_radius": "critical"},
                ],
            }
        )


def test_rejects_invalid_default_value():
    with pytest.raises(ValueError):
        PolicyEngine({"defaults": {"remediation": "not-a-real-severity"}, "rules": []})


def test_rejects_rule_missing_blast_radius():
    with pytest.raises(ValueError):
        PolicyEngine({"defaults": {}, "rules": [{"id": "no-br", "match": {}}]})
