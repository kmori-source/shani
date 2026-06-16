"""
Shani Generic Adapter.

Makes any existing agent tool Shani-governed without modifying it.

Pattern: Wrap, don't modify.

    # BEFORE (ungoverned)
    def restart_service(service_name: str) -> str:
        ...

    # AFTER (Shani-governed) — original function untouched
    governed = ShaniToolWrapper(
        fn=restart_service,
        decision_type=DecisionType.CONFIGURATION_CHANGE,
        target_extractor=lambda kwargs: f"service:{kwargs['service_name']}",
        blast_radius=BlastRadius.LIMITED,
        gate=hitl_gate,
        proposed_by="ops-agent/v1",
    )
    governed(service_name="nginx")

For LangChain: use LangChainShaniToolWrapper
For AutoGen: use AutoGenShaniAdapter
For any framework: use ShaniToolWrapper directly
"""

from __future__ import annotations

import functools
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ...schemas.decision import (
    DecisionProposal,
    DecisionType,
    BlastRadius,
    DecisionScope,
    EvidenceItem,
)
from ...schemas.state import DIS
from ...core.evaluator import DeniedDecision, ShaniEvaluator
from ...hitl.approval.gate import HITLGate

logger = logging.getLogger("shani.adapter")

# Either a ShaniEvaluator or a HITLGate
GovernanceGate = ShaniEvaluator | HITLGate


class GovernedToolError(Exception):
    """Raised when Shani denies execution of a governed tool."""


class ShaniToolWrapper:
    """
    Wraps any callable with Shani governance.

    The wrapped function is not modified.
    The wrapper intercepts the call, proposes a decision to Shani,
    and only calls the original function if authorized.

    This is the core "add-on" mechanism.
    """

    def __init__(
        self,
        fn: Callable,
        gate: GovernanceGate,
        decision_type: DecisionType,
        blast_radius: BlastRadius,
        proposed_by: str,
        target_extractor: Callable[[dict], str] | str = "unknown",
        description_template: str | None = None,
        evidence_extractor: Callable[[dict], list[EvidenceItem]] | None = None,
        confidence: float = 0.8,
        reversibility: bool = True,
        timeout_minutes: int = 15,
        raise_on_deny: bool = True,
        parent_decision_id: str | None = None,
    ) -> None:
        self._fn = fn
        self._gate = gate
        self._decision_type = decision_type
        self._blast_radius = blast_radius
        self._proposed_by = proposed_by
        self._target_extractor = target_extractor
        self._description_template = description_template or fn.__doc__ or fn.__name__
        self._evidence_extractor = evidence_extractor
        self._confidence = confidence
        self._reversibility = reversibility
        self._timeout_minutes = timeout_minutes
        self._raise_on_deny = raise_on_deny
        self._parent_decision_id = parent_decision_id

        functools.update_wrapper(self, fn)

    def __call__(self, *args, **kwargs) -> Any:
        # Build proposal from call arguments
        proposal = self._build_proposal(args, kwargs)

        # Submit to gate (evaluator or HITL)
        result = self._gate.evaluate(proposal)

        if isinstance(result, DeniedDecision):
            logger.warning(
                "Governed tool DENIED | fn=%s reason=%s",
                self._fn.__name__,
                result.reason,
            )
            if self._raise_on_deny:
                raise GovernedToolError(
                    f"Shani denied execution of '{self._fn.__name__}': {result.reason}"
                )
            return None

        # Verify binding before execution
        if not self._gate.verify_binding(result):
            raise GovernedToolError(f"ADO binding verification failed for {self._fn.__name__}")

        logger.info(
            "Governed tool EXECUTING | fn=%s dsal=%s target=%s",
            self._fn.__name__,
            result.authorized_dsal,
            result.intent_binding.target,
        )

        try:
            output = self._fn(*args, **kwargs)
            self._gate.register_executed(result, agent_id=self._proposed_by)
            return output
        except Exception as e:
            logger.error("Governed tool FAILED | fn=%s error=%s", self._fn.__name__, e)
            raise

    def _build_proposal(self, args: tuple, kwargs: dict) -> DecisionProposal:
        all_kwargs = dict(zip(self._fn.__code__.co_varnames, args))
        all_kwargs.update(kwargs)

        if callable(self._target_extractor):
            target = self._target_extractor(all_kwargs)
        else:
            target = str(self._target_extractor)

        evidence = []
        if self._evidence_extractor:
            evidence = self._evidence_extractor(all_kwargs)

        description = (
            self._description_template.format(**all_kwargs)
            if "{" in self._description_template
            else self._description_template
        )

        return DecisionProposal(
            decision_type=self._decision_type,
            proposed_by=self._proposed_by,
            description=description,
            target=target,
            scope=DecisionScope(asset_ids=[target]),
            evidence=evidence,
            confidence=self._confidence,
            reversibility=self._reversibility,
            blast_radius=self._blast_radius,
            parent_decision_id=self._parent_decision_id,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=self._timeout_minutes),
        )


def governed_tool(
    gate: GovernanceGate,
    decision_type: DecisionType,
    blast_radius: BlastRadius,
    proposed_by: str,
    target_extractor: Callable[[dict], str] | str = "unknown",
    **kwargs,
) -> Callable:
    """
    Decorator version of ShaniToolWrapper.

        @governed_tool(
            gate=hitl_gate,
            decision_type=DecisionType.REMEDIATION,
            blast_radius=BlastRadius.LIMITED,
            proposed_by="my-agent/v1",
            target_extractor=lambda kw: f"host:{kw['host']}",
        )
        def quarantine_host(host: str) -> str:
            ...
    """

    def decorator(fn: Callable) -> ShaniToolWrapper:
        return ShaniToolWrapper(
            fn=fn,
            gate=gate,
            decision_type=decision_type,
            blast_radius=blast_radius,
            proposed_by=proposed_by,
            target_extractor=target_extractor,
            **kwargs,
        )

    return decorator
