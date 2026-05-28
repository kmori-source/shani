"""
shani.runtime.evaluator — Core evaluation engine.

Re-exports from shani.core.evaluator (Phase 3 logical split).
Physical file migration is a follow-up step.

Usage:
    from shani.runtime.evaluator import ShaniEvaluator, DeniedDecision
"""
from shani.core.evaluator import (
    ShaniEvaluator,
    DeniedDecision,
    EvaluationResult,
    AuthorityProvider,
)

__all__ = [
    "ShaniEvaluator",
    "DeniedDecision",
    "EvaluationResult",
    "AuthorityProvider",
]
