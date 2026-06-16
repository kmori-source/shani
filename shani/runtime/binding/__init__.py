"""
shani.runtime.binding — Authority and boundary enforcement layer.

Re-exports from shani.authority and shani.boundary (Phase 3 logical split).
"binding" = the layer that binds agent authority to policy and decision scope.

Usage:
    from shani.runtime.binding import (
        DecisionPolicyProvider, AgentIdentity,
        DecisionBoundary, DecisionFirewall,
        StaticAuthorityProvider, YAMLAuthorityProvider,
    )
"""

from shani.authority.provider import StaticAuthorityProvider, YAMLAuthorityProvider
from shani.authority.policy import (
    DecisionPolicyProvider,
    AgentIdentity,
    OrgPolicy,
    OrgPolicyAbsoluteConstraints,
)
from shani.boundary.hook import (
    DecisionBoundary,
    DecisionFirewall,
    DecisionBoundaryViolation,
    PrincipalNotificationChannel,
)
from shani.boundary.capability import (
    Capability,
    ExecutionBoundary,
    CapabilityError,
)

__all__ = [
    "StaticAuthorityProvider",
    "YAMLAuthorityProvider",
    "DecisionPolicyProvider",
    "AgentIdentity",
    "OrgPolicy",
    "OrgPolicyAbsoluteConstraints",
    "DecisionBoundary",
    "DecisionFirewall",
    "DecisionBoundaryViolation",
    "PrincipalNotificationChannel",
    "Capability",
    "ExecutionBoundary",
    "CapabilityError",
]
