"""
shani.runtime.dis — Distributed Integrity State (DIS) monitor.

Re-exports from shani.integrity (Phase 3 logical split).
"dis" = Decision Integrity State, the runtime health automaton.

Usage:
    from shani.runtime.dis import DISIntegrityMonitor, IntegritySignal
"""
from shani.integrity.monitor import (
    DISIntegrityMonitor,
    IntegritySignal,
    IntegritySignalType,
    SignalSeverity,
)
from shani.schemas.state import DIS, DSAL, DISStateMachine

__all__ = [
    "DISIntegrityMonitor",
    "IntegritySignal",
    "IntegritySignalType",
    "SignalSeverity",
    "DIS",
    "DSAL",
    "DISStateMachine",
]
