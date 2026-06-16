"""
shani.runtime — Runtime components of the Shani governance layer.

This namespace provides access to core runtime modules that enforce
decision governance at agent execution time.

Sub-packages:
    evaluator      Core evaluation engine (ShaniEvaluator, DeniedDecision)
    posture_engine Posture binding layer (PostureEngine, PostureSimulation)
    dis            Distributed Integrity State monitor
    binding        Authority and boundary enforcement

These re-export from the canonical shani.* modules for backward
compatibility. Physical file migration tracked in Phase 3 issue.
"""

from . import evaluator, posture_engine, dis, binding

__all__ = ["evaluator", "posture_engine", "dis", "binding"]
