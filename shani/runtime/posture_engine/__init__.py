"""
shani.runtime.posture_engine — Posture binding layer (SPEC §8.4).

Re-exports from shani.posture (Phase 3 logical split).

Usage:
    from shani.runtime.posture_engine import PostureEngine, PostureSimulation
"""
from shani.posture.engine import PostureEngine
from shani.posture.simulation import PostureSimulation
from shani.schemas.posture import (
    UserPosture,
    PostureConstraints,
    PostureHistoryEntry,
    PostureOutcome,
    PostureRefinementRequest,
    PostureSimulationResult,
)

__all__ = [
    "PostureEngine",
    "PostureSimulation",
    "UserPosture",
    "PostureConstraints",
    "PostureHistoryEntry",
    "PostureOutcome",
    "PostureRefinementRequest",
    "PostureSimulationResult",
]
