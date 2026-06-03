"""
shani/posture/simulation.py

PostureSimulation — pre-signing requirement (SPEC §8.6).

Before a principal signs or updates a UserPosture, a conforming
implementation MUST run a PostureSimulation. This prevents Binding Theater:
signing a Posture declaration without understanding its operational consequences.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..schemas.decision import DecisionProposal
from ..schemas.posture import (
    PostureOutcome,
    PostureSimulationResult,
    UserPosture,
)
from .engine import PostureEngine


class PostureSimulation:
    """
    Runs a candidate UserPosture against a sample of historical proposals.

    Conformance requirements (SPEC §8.6):
    - Produce pass_count, reject_count, ambiguous_count
    - Include at least 3 reject_examples if any rejections exist
    - Include a delta_vs_current comparison if current posture is provided
    """

    def run(
        self,
        candidate_posture:     UserPosture,
        historical_proposals:  list[DecisionProposal],
        current_posture:       UserPosture | None = None,
    ) -> PostureSimulationResult:
        """
        Evaluate all historical_proposals under candidate_posture.

        Returns a PostureSimulationResult. The simulation_id of this result
        should be stored in UserPosture.simulation_ref before signing.
        """
        engine = PostureEngine(candidate_posture)

        pass_list:      list[dict[str, Any]] = []
        reject_list:    list[dict[str, Any]] = []
        ambiguous_list: list[dict[str, Any]] = []

        for prop in historical_proposals:
            outcome, _ = engine.evaluate(prop)
            record: dict[str, Any] = {
                "decision_id":  prop.decision_id,
                "target":       prop.target,
                "blast_radius": prop.blast_radius.value,
                "reversibility": prop.reversibility,
                "evidence_count": len(prop.evidence),
            }
            if outcome == PostureOutcome.PASS:
                pass_list.append(record)
            elif outcome == PostureOutcome.REJECT:
                reject_list.append(record)
            else:
                ambiguous_list.append(record)

        delta: dict[str, Any] | None = None
        if current_posture is not None:
            current_engine = PostureEngine(current_posture)
            current_reject = sum(
                1 for p in historical_proposals
                if current_engine.evaluate(p)[0] == PostureOutcome.REJECT
            )
            delta = {
                "new_reject_count":     len(reject_list),
                "current_reject_count": current_reject,
                "delta":                len(reject_list) - current_reject,
            }

        return PostureSimulationResult(
            simulation_id=str(uuid.uuid4()),
            posture_version=candidate_posture.version,
            principal_id=candidate_posture.principal_id,
            pass_count=len(pass_list),
            reject_count=len(reject_list),
            ambiguous_count=len(ambiguous_list),
            # SPEC requires at least 3 reject examples if any exist
            reject_examples=reject_list[:3],
            pass_examples=pass_list[:3],
            ambiguous_examples=ambiguous_list[:3],
            delta_vs_current=delta,
        )
