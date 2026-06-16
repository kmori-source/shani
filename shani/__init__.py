"""
Shani — Autonomous Decision Governance Layer.

Add-on usage (Human-in-the-Loop):

    from shani import ShaniEvaluator, StaticAuthorityProvider
    from shani.hitl import HITLGate
    from shani.hitl.channel import CallbackApprovalChannel, CLIApprovalChannel
    from shani.adapters.generic import governed_tool, ShaniToolWrapper
    from shani.adapters.langchain import patch_langchain_tools
    from shani.adapters.autogen import patch_autogen_agent

Spec: spec/shani-v0.4.md
"""

from . import _bootstrap  # inject pydantic shim when pydantic is absent

from .core.evaluator import ShaniEvaluator, DeniedDecision
from .boundary.hook import (
    DecisionBoundary,
    DecisionFirewall,
    DecisionBoundaryViolation,
    PrincipalNotificationChannel,
)
from .schemas.decision import (
    DecisionProposal,
    AuthorizedDecisionObject,
    DecisionType,
    BlastRadius,
    DecisionScope,
    EvidenceItem,
    IntentBinding,
)
from .schemas.state import DIS, DSAL, DISStateMachine
from .schemas.posture import (
    UserPosture,
    PostureConstraints,
    PostureHistoryEntry,
    PostureOutcome,
    PostureRefinementRequest,
    PostureSimulationResult,
)
from .authority.provider import YAMLAuthorityProvider, StaticAuthorityProvider
from .authority.policy import (
    DecisionPolicyProvider,
    AgentIdentity,
    OrgPolicy,
    OrgPolicyAbsoluteConstraints,
)
from .posture.engine import PostureEngine
from .posture.simulation import PostureSimulation
from .crypto.signing import SigningKeypair, ADOSigner, ADOChainVerifier, ADOSignatureChain
from .integrity.monitor import (
    DISIntegrityMonitor,
    IntegritySignal,
    IntegritySignalType,
    SignalSeverity,
)

__version__ = "0.4.0"
__spec_version__ = "0.4"
SPEC_VERSION = "0.4"  # Conformance declaration (SPEC §7): this implementation conforms to SPEC v0.4

__all__ = [
    "SPEC_VERSION",
    "ShaniEvaluator",
    "DeniedDecision",
    "DecisionBoundary",
    "DecisionFirewall",
    "DecisionBoundaryViolation",
    "PrincipalNotificationChannel",
    "DecisionProposal",
    "AuthorizedDecisionObject",
    "DecisionType",
    "BlastRadius",
    "DecisionScope",
    "EvidenceItem",
    "IntentBinding",
    "DIS",
    "DSAL",
    "DISStateMachine",
    # v0.4 Binding Layer
    "UserPosture",
    "PostureConstraints",
    "PostureHistoryEntry",
    "PostureOutcome",
    "PostureRefinementRequest",
    "PostureSimulationResult",
    "PostureEngine",
    "PostureSimulation",
    "OrgPolicy",
    "OrgPolicyAbsoluteConstraints",
    "YAMLAuthorityProvider",
    "StaticAuthorityProvider",
    "DecisionPolicyProvider",
    "AgentIdentity",
    "SigningKeypair",
    "ADOSigner",
    "ADOChainVerifier",
    "ADOSignatureChain",
    "DISIntegrityMonitor",
    "IntegritySignal",
    "IntegritySignalType",
    "SignalSeverity",
]
