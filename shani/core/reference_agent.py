"""
Shani Reference Execution Agent.

This agent is intentionally minimal ("super stupid").

Its only purpose is to demonstrate that an agent cannot act
without a valid Authorized Decision Object from Shani.

It does not plan. It does not reason. It does not optimize.
It accepts an ADO and executes within its constraints.
"""

from __future__ import annotations

import sys
import logging

from ..schemas.decision import AuthorizedDecisionObject
from ..boundary.hook import DecisionBoundary, DecisionBoundaryViolation

logger = logging.getLogger("shani.reference_agent")


class ReferenceExecutionAgent:
    """
    Minimal agent that enforces the Shani contract.

    Design invariant: Without an ADO, this agent does nothing.
    This is a feature, not a limitation.
    """

    def __init__(self, boundary: DecisionBoundary, agent_id: str = "reference-agent-v1") -> None:
        self._boundary = boundary
        self._agent_id = agent_id

    def execute(self, ado: AuthorizedDecisionObject, dry_run: bool = False) -> dict:
        """
        Execute under the authority of an Authorized Decision Object.

        Validates:
          1. ADO is present
          2. ADO binding hash is valid
          3. ADO has not expired
          4. D-SAL constraints are respected

        Then simulates execution (replace stub with real logic).
        """

        # Boundary enforces all ADO checks
        @self._boundary.enforce
        def _execute(ado: AuthorizedDecisionObject, dry_run: bool) -> dict:
            dsal = ado.authorized_dsal
            constraints = ado.constraints

            logger.info(
                "[%s] Executing decision %s at D-SAL %s | dry_run=%s",
                self._agent_id,
                ado.decision_id,
                dsal,
                dry_run,
            )

            if dry_run:
                logger.info("[%s] DRY RUN — no action taken.", self._agent_id)
                return {
                    "status": "dry_run",
                    "decision_id": ado.decision_id,
                    "authorized_dsal": dsal,
                    "constraints_observed": constraints,
                }

            # --- Execution stub ---
            # Replace this block with real agent logic.
            # This agent is intentionally dumb.
            result = self._dispatch(ado)
            # ----------------------

            return {
                "status": "executed",
                "decision_id": ado.decision_id,
                "authorized_dsal": dsal,
                "result": result,
            }

        try:
            return _execute(ado, dry_run)
        except DecisionBoundaryViolation as e:
            logger.error("[%s] BOUNDARY VIOLATION: %s", self._agent_id, e)
            # Hard exit on boundary violations — agents must not swallow these
            sys.exit(1)

    def _dispatch(self, ado: AuthorizedDecisionObject) -> str:
        """
        Stub dispatcher. In a real agent, route by decision_type.
        """
        return f"Action completed for decision {ado.decision_id}"
