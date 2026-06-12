"""
Shani Decision Policy — DecisionType → Required D-SAL mapping.

Core design correction:
    BEFORE (wrong): Agent → D-SAL  (agent holds a fixed autonomy level)
    AFTER  (right):
        Decision → required_dsal   (each decision type demands a minimum D-SAL)
        Agent    → granted_dsal    (agent holds a granted ceiling)

    Authorization logic:
        if agent.granted_dsal >= decision.required_dsal:
            allow
        else:
            deny

This makes Shani a true Authorization Kernel:
    - The decision type determines the governance overhead required
    - The agent's granted level determines what it can do
    - Neither alone is sufficient

Example decision_policy.yaml:

    decision_policy:
      remediation: 1
      configuration_change: 2
      data_access: 1
      network_action: 2
      delegation: 3
      policy_update: 4

    agent_registry:
      monitor-agent/v1:
        granted_dsal: 2
        allowed_decision_types:
          - remediation
          - configuration_change
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


from ..schemas.decision import DecisionType
from ..schemas.posture import PostureConstraints, UserPosture
from .dsal_calculator import DSALCalculator, DSALCalculation


# ---------------------------------------------------------------------------
# OrgPolicy — absolute constraints ceiling (SPEC §8.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrgPolicyAbsoluteConstraints:
    """
    Organization-defined upper bounds on what any UserPosture may declare.

    Cannot be overridden by individual principals.
    Enforced at UserPosture registration and at PostureEngine evaluation.
    """
    max_blast_radius:    str  = "critical"   # no UserPosture may exceed this
    cross_org_min_dsal:  int  = 4            # minimum D-SAL for cross-org transitions
    prod_reversibility:  bool = False        # if True, irreversible ops on prod are always denied
    prod_target_pattern: str  = r"prod.*"    # regex pattern identifying production targets


@dataclass(frozen=True)
class OrgPolicy:
    """
    Organization-level governance policy.

    Contains absolute_constraints that form the ceiling of all UserPostures
    in the organization (SPEC §8.3).
    """
    absolute_constraints: OrgPolicyAbsoluteConstraints = field(
        default_factory=OrgPolicyAbsoluteConstraints
    )


# ---------------------------------------------------------------------------
# Default policy — conservative, explicit
# ---------------------------------------------------------------------------

# Mirrors policy/decision_policy.yaml — keep in sync
DEFAULT_DECISION_POLICY: dict[str, int] = {
    DecisionType.REMEDIATION.value:          1,
    DecisionType.CONFIGURATION_CHANGE.value: 2,
    DecisionType.DATA_ACCESS.value:          1,  # Read-only: minimal oversight
    DecisionType.NETWORK_ACTION.value:       2,
    DecisionType.DELEGATION.value:           3,
    DecisionType.POLICY_UPDATE.value:        4,
    DecisionType.BROWSER_ACTION.value:       2,  # Browser automation: supervised
    DecisionType.AGENT_TASK.value:           1,  # nanoclaw agent tools: bounded
    DecisionType.TOOL_CALL.value:            1,  # cowork/Claude API: bounded
}


# ---------------------------------------------------------------------------
# Agent identity record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentIdentity:
    """
    A registered agent's identity and granted authority.

    Agents must be pre-registered. Unregistered agents are denied by default.

    In v0.4, the optional `binding` field marks this entry as a signed
    declaration document (SPEC §8.7). When present, it contains the
    principal's UserPosture and history.
    """
    agent_id:               str
    granted_dsal:           int                           # Ceiling of what this agent may do
    public_key_b64:         str | None = None             # Ed25519 public key for identity binding
    allowed_decision_types: frozenset[str] = field(default_factory=frozenset)
    metadata:               dict[str, Any] = field(default_factory=dict)
    binding:                UserPosture | None = None     # v0.4: signed declaration (optional)


# ---------------------------------------------------------------------------
# Decision Policy Provider
# ---------------------------------------------------------------------------


class CapabilityMatrix:
    """
    manages the capability_matrix section of policy.yaml. Part of Policy.

    ExecutionBoundary only reads from here。
    no hardcoded permission mappings exist in the code。
    """
    # Mirrors policy/decision_policy.yaml capability_matrix — keep in sync
    _FALLBACK: dict[str, set[str]] = {
        "data_access":          {"http_get", "read_file"},
        "configuration_change": {"http_post", "http_put", "write_file"},
        "remediation":          {"run_command", "http_post", "write_file"},
        "network_action":       {"http_get", "http_post", "http_put"},
        "delegation":           {"http_post"},
        "policy_update":        {"http_post", "http_put", "write_file"},
        "browser_action":       {"http_get", "http_post"},
        "agent_task":           {"http_get", "http_post", "read_file", "run_command"},
        "tool_call":            {"http_get", "http_post", "read_file", "run_command"},
    }

    def __init__(self, matrix_data: "dict | None" = None):
        import logging
        self._log = logging.getLogger("shani.authority.capability_matrix")
        if matrix_data:
            self._matrix: dict[str, set[str]] = {
                dt: set(entry.get("operations", []))
                for dt, entry in matrix_data.items()
            }
        else:
            self._matrix = {k: set(v) for k, v in self._FALLBACK.items()}

    def get_operations(self, decision_type: str) -> set[str]:
        ops = self._matrix.get(decision_type)
        if ops is None:
            self._log.warning(
                "No capability_matrix entry for '%s' — denying. "
                "Add to policy.yaml.", decision_type
            )
            return set()
        return set(ops)

    def known_types(self) -> list[str]:
        return sorted(self._matrix.keys())


class DecisionPolicyProvider:
    """
    Provides:
        1. required_dsal(decision_type) → int
        2. agent_identity(agent_id) → AgentIdentity | None
        3. authorize(agent_id, decision_type) → (allowed: bool, reason: str)

    Authorization rule:
        agent.granted_dsal >= decision.required_dsal
        AND decision_type in agent.allowed_decision_types (if restricted)
    """

    def __init__(
        self,
        decision_policy:           dict[str, int] | None = None,
        agent_registry:            dict[str, AgentIdentity] | None = None,
        allow_unregistered_agents: bool = False,
        capability_matrix:         "CapabilityMatrix | None" = None,
        environment_rules:         "dict | None" = None,
        org_policy:                OrgPolicy | None = None,
        kill_switch_enabled:       bool = False,
    ) -> None:
        self._policy = decision_policy or DEFAULT_DECISION_POLICY.copy()
        self._agents = agent_registry or {}
        self._allow_unregistered = allow_unregistered_agents
        self._capability_matrix = capability_matrix or CapabilityMatrix()
        self._environment_rules = environment_rules  # passed to DSALCalculator
        self._org_policy = org_policy or OrgPolicy()
        self._kill_switch_enabled = kill_switch_enabled

    @classmethod
    def from_yaml(cls, path: Path | str) -> "DecisionPolicyProvider":
        """Load policy and agent registry from a YAML config file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Decision policy config not found: {p}")

        with p.open() as f:
            import yaml
            data: dict[str, Any] = yaml.safe_load(f)

        # Parse decision policy
        raw_policy = data.get("decision_policy", {})
        policy = {k: int(v) for k, v in raw_policy.items()}

        # Parse agent registry (v0.4: includes optional binding section)
        agents: dict[str, AgentIdentity] = {}
        for agent_id, agent_data in data.get("agent_registry", {}).items():
            allowed = frozenset(agent_data.get("allowed_decision_types", []))
            binding: UserPosture | None = None
            if "binding" in agent_data:
                binding = cls._parse_binding(agent_data["binding"])
            agents[agent_id] = AgentIdentity(
                agent_id=agent_id,
                granted_dsal=int(agent_data.get("granted_dsal", 0)),
                public_key_b64=agent_data.get("public_key_b64"),
                allowed_decision_types=allowed,
                metadata=agent_data.get("metadata", {}),
                binding=binding,
            )

        # Parse org_policy absolute_constraints (SPEC §8.3)
        org_policy = cls._parse_org_policy(data.get("org_policy", {}))

        allow_unreg = bool(data.get("allow_unregistered_agents", False))
        kill_switch = bool(data.get("kill_switch", False))
        provider = cls(
            decision_policy=policy,
            agent_registry=agents,
            allow_unregistered_agents=allow_unreg,
            capability_matrix=CapabilityMatrix(data.get("capability_matrix")),
            environment_rules=data.get("environment_rules"),
            org_policy=org_policy,
            kill_switch_enabled=kill_switch,
        )

        # Validate all binding entries against org_policy at registration time.
        # Verify posture_signature when the agent's public key is available.
        for agent_id, identity in agents.items():
            if identity.binding is not None:
                pub_key: bytes | None = None
                if identity.public_key_b64 is not None:
                    import base64 as _b64
                    try:
                        pub_key = _b64.b64decode(identity.public_key_b64)
                    except Exception:
                        pass
                ok, reason = provider.validate_user_posture(identity.binding, public_key_bytes=pub_key)
                if not ok:
                    raise ValueError(
                        f"agent_registry['{agent_id}'].binding violates "
                        f"OrgPolicy.absolute_constraints: {reason}"
                    )

        return provider

    @staticmethod
    def _parse_binding(binding_data: dict) -> UserPosture:
        """Parse a binding section from agent_registry into a UserPosture."""
        from datetime import datetime, timezone
        from ..schemas.posture import PostureHistoryEntry

        posture_data = binding_data.get("posture", {})
        constraints = PostureConstraints(
            target_scope=posture_data.get("target_scope", ".*"),
            max_blast_radius=posture_data.get("max_blast_radius", "critical"),
            reversibility_required=bool(posture_data.get("reversibility_required", False)),
            minimum_evidence=int(posture_data.get("minimum_evidence", 0)),
        )

        history_entries: list[PostureHistoryEntry] = []
        for h in binding_data.get("history", []):
            signed_at = h.get("signed_at")
            if isinstance(signed_at, str):
                signed_at = datetime.fromisoformat(signed_at)
            history_entries.append(PostureHistoryEntry(
                version=str(h.get("version", "")),
                signed_at=signed_at,
                note=str(h.get("note", "")),
            ))
        history_tuple = tuple(history_entries)

        signed_at = binding_data.get("signed_at")
        if isinstance(signed_at, str):
            signed_at = datetime.fromisoformat(signed_at)

        return UserPosture(
            version=str(binding_data.get("version", "1.0")),
            principal_id=str(binding_data.get("principal_id", "")),
            signed_at=signed_at,
            intent_statement=str(binding_data.get("intent_statement", "")),
            simulation_ref=str(binding_data.get("simulation_ref", "")),
            constraints=constraints,
            history=history_tuple,
            posture_signature=binding_data.get("posture_signature"),
        )

    @staticmethod
    def _parse_org_policy(org_policy_data: dict) -> OrgPolicy:
        """Parse an org_policy section from YAML."""
        ac_data = org_policy_data.get("absolute_constraints", {})
        return OrgPolicy(
            absolute_constraints=OrgPolicyAbsoluteConstraints(
                max_blast_radius=ac_data.get("max_blast_radius", "critical"),
                cross_org_min_dsal=int(ac_data.get("cross_org_min_dsal", 4)),
                prod_reversibility=bool(ac_data.get("prod_reversibility", False)),
                prod_target_pattern=ac_data.get("prod_target_pattern", r"prod.*"),
            )
        )

    @property
    def kill_switch_enabled(self) -> bool:
        """Kill switch state loaded from config (SPEC §4.7)."""
        return self._kill_switch_enabled

    @property
    def capability_matrix(self) -> "CapabilityMatrix":
        """CapabilityMatrix referenced by ExecutionBoundary."""
        return self._capability_matrix

    @property
    def environment_rules(self) -> "dict | None":
        """Environment rules referenced by DSALCalculator."""
        return self._environment_rules

    @property
    def org_policy(self) -> OrgPolicy:
        """OrgPolicy containing absolute_constraints ceiling."""
        return self._org_policy

    def validate_user_posture(
        self,
        posture: "UserPosture",
        public_key_bytes: bytes | None = None,
        simulation_store: "dict | None" = None,
    ) -> tuple[bool, str]:
        """
        Validate a UserPosture against OrgPolicy.absolute_constraints.

        Called at registration time and at PostureEngine evaluation.
        Returns (ok, reason). If ok is False, reason explains the violation.

        Normative requirements (SPEC §8.2, §8.6, §8.7):
        - Must have simulation_ref
        - simulation_ref must reference a known PostureSimulationResult when
          simulation_store is provided (SPEC §8.6)
        - Constraints must not exceed absolute_constraints ceiling
        - posture_signature must be present and is verified when public_key_bytes
          is supplied (SPEC §8.2)
        """
        import logging as _logging
        _log = _logging.getLogger("shani.authority.policy")

        ac = self._org_policy.absolute_constraints

        # Require simulation_ref
        if not posture.simulation_ref.strip():
            return False, "UserPosture must have a non-empty simulation_ref."

        # Validate simulation_ref references a real PostureSimulationResult (SPEC §8.6)
        if simulation_store is not None:
            if posture.simulation_ref not in simulation_store:
                return False, (
                    f"UserPosture simulation_ref '{posture.simulation_ref}' does not "
                    "reference a known PostureSimulationResult (SPEC §8.6). "
                    "Run PostureSimulation before signing."
                )

        # Require principal_id and signed_at (SPEC §8.7)
        if not posture.principal_id.strip():
            return False, "UserPosture must have a non-empty principal_id."
        if posture.signed_at is None:
            return False, "UserPosture must have a signed_at (SPEC §8.7)."

        _blast_order = ["isolated", "limited", "significant", "critical"]

        # max_blast_radius must not exceed org ceiling
        posture_br = posture.constraints.max_blast_radius.lower()
        org_br     = ac.max_blast_radius.lower()
        if posture_br not in _blast_order or org_br not in _blast_order:
            return False, f"Unknown blast_radius value: {posture_br!r} or {org_br!r}"
        if _blast_order.index(posture_br) > _blast_order.index(org_br):
            return False, (
                f"UserPosture.max_blast_radius '{posture_br}' exceeds "
                f"OrgPolicy.absolute_constraints.max_blast_radius '{org_br}'."
            )

        # Cryptographic signature check (SPEC §8.2, §8.7): "Must be signed."
        if posture.posture_signature is None:
            return False, (
                f"UserPosture for principal '{posture.principal_id}' must be signed "
                "(posture_signature is required per SPEC §8.2, §8.7)."
            )
        if public_key_bytes is not None:
            if not posture.verify_signature(public_key_bytes):
                return False, "UserPosture posture_signature verification failed."

        return True, "OK"

    def required_dsal(self, decision_type: DecisionType | str) -> int:
        """Return the minimum D-SAL required for this decision type."""
        key = decision_type.value if isinstance(decision_type, DecisionType) else decision_type
        if key not in self._policy:
            # Unknown decision type: require maximum D-SAL (fail secure)
            return 4
        return self._policy[key]

    def agent_identity(self, agent_id: str) -> AgentIdentity | None:
        return self._agents.get(agent_id)

    def authorize(
        self,
        agent_id: str,
        decision_type: DecisionType | str,
        effective_dsal: int,
    ) -> tuple[bool, str]:
        """
        Authorization check against effective D-SAL (computed by DSALCalculator).

        Agents do not declare their own D-SAL。
        effective_dsal is computed from context by DSALCalculator and passed in.

        Conditions:
            1. agent.granted_dsal >= effective_dsal
            2. decision_type is in the agent's allowed_decision_types
        """
        dt_key = decision_type.value if isinstance(decision_type, DecisionType) else decision_type

        identity = self.agent_identity(agent_id)
        if identity is None:
            if not self._allow_unregistered:
                return False, (
                    f"Agent '{agent_id}' is not registered. "
                    "Register the agent in agent_registry to proceed."
                )
            granted = 0
            allowed_types: frozenset[str] = frozenset()
        else:
            granted = identity.granted_dsal
            allowed_types = identity.allowed_decision_types

        # Decision type whitelist
        if allowed_types and dt_key not in allowed_types:
            return False, (
                f"Agent '{agent_id}' is not authorized for decision type '{dt_key}'. "
                f"Allowed types: {sorted(allowed_types)}"
            )

        # deny if effective_dsal exceeds the agent's granted level
        if effective_dsal > granted:
            return False, (
                f"Effective D-SAL {effective_dsal} exceeds agent '{agent_id}' "
                f"granted D-SAL {granted}. "
                "Reduce blast_radius, add evidence, or use a higher-privileged agent."
            )

        return True, "OK"
