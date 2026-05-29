# Shani Policy Reference

`policy/decision_policy.yaml` is the Single Source of Truth for all Shani governance parameters. No code changes are required to configure Shani for your organization.

---

## Section 1: decision_policy

Maps each DecisionType to a base D-SAL (the minimum before context modifiers apply).

```yaml
decision_policy:
  remediation:          1   # Bounded: low-level fix (restart, patch)
  configuration_change: 2   # Supervised: system settings
  data_access:          1   # Read-only operations
  network_action:       3   # Policy-governed: firewall, routing
  delegation:           3   # Sub-agent spawning
  policy_update:        4   # Governance itself — always D-SAL 4
```

**D-SAL levels:**

| Level | Name | Typical approval |
|---|---|---|
| 0 | Autonomous | No oversight |
| 1 | Logged | Automatic, logged |
| 2 | Supervised | SecOps review |
| 3 | Policy-governed | Policy document required |
| 4 | Board-level | Explicit human authorization |

**Adding a custom DecisionType:**

```yaml
decision_policy:
  my_database_migration: 3   # custom type, requires D-SAL 3
```

Then add it to `capability_matrix` (see Section 2).

---

## Section 2: capability_matrix

Maps each DecisionType to the set of operations a Capability may perform.

```yaml
capability_matrix:
  data_access:
    operations: [http_get, read_file]
    note: "Read-only. No writes, no commands."

  configuration_change:
    operations: [http_post, http_put, write_file]
    note: "Configuration writes. No deletion, no commands."

  remediation:
    operations: [run_command, http_post, write_file]
    note: "Remediation. No deletion."

  network_action:
    operations: [http_get, http_post, http_put]
    note: "Network ops. No filesystem access."

  delegation:
    operations: [http_post]
    note: "Delegation only. No direct execution."

  policy_update:
    operations: [http_post, http_put, write_file]
    note: "Policy updates. Always D-SAL 4."
```

**Available operations:**

| Operation | Description | Risk |
|---|---|---|
| `http_get` | HTTP GET (read) | Low |
| `http_post` | HTTP POST (create) | Medium |
| `http_put` | HTTP PUT (update) | Medium |
| `http_delete` | HTTP DELETE | High |
| `read_file` | File read | Low |
| `write_file` | File write/create | Medium |
| `delete_file` | File deletion | High |
| `run_command` | Shell command | Highest |

**Adding a custom type with custom operations:**

```yaml
capability_matrix:
  my_database_migration:
    operations: [http_post, write_file]
    note: "DB migration: API trigger + config write only"
```

Unknown DecisionTypes return empty operations (fail secure).

---

## Section 3: environment_rules

Defines what constitutes a high-risk environment. Targets containing these keywords trigger a D-SAL increase.

```yaml
environment_rules:
  high_risk_keywords:
    - prod
    - production
    - live
    - prd
    - main
    - master
    # Add your organization's keywords:
    # - customer-data
    # - main-cluster
    # - regulated
    # - pci
    # - phi
    # - gdpr-scope
  medium_risk_keywords: []   # reserved for future use
```

**How it works:**

The `environment` dimension in RiskAssessor checks whether the proposal's `target` field contains any of these keywords (case-insensitive). A match raises the environment risk score, which raises `effective_dsal`.

**Example:** If your cluster is named `main-cluster-eu-west`, add `main-cluster` to `high_risk_keywords`.

---

## Section 4: authority_roles

Maps D-SAL levels to human role names. These names appear in HITL notifications (Slack, email, CLI).

```yaml
authority_roles:
  0: "any-operator"
  1: "SOC-Analyst"
  2: "SecOps-Lead"
  3: "Org-Policy"
  4: "Board-Level"
```

**Customize for your organization:**

```yaml
authority_roles:
  0: "any-sre"
  1: "sre-on-call"
  2: "security-engineer"
  3: "ciso"
  4: "board-approval"
```

These names are resolved via `authority_provider.resolve_authority(dsal)`. No code changes required.

---

## Section 5: agent_registry

Registers AI agents and their granted permissions.

```yaml
allow_unregistered_agents: false   # true only for development

agent_registry:

  my-agent/v1:
    granted_dsal: 2                # max D-SAL this agent can reach
    public_key_b64: null           # Ed25519 public key (production)
    allowed_decision_types:
      - remediation
      - configuration_change
    metadata:
      team: platform
      environment: production
```

**Fields:**

| Field | Required | Description |
|---|---|---|
| `granted_dsal` | Yes | Ceiling D-SAL for this agent |
| `allowed_decision_types` | Yes | Whitelist of permitted DecisionTypes |
| `public_key_b64` | No | Ed25519 public key for identity verification |
| `metadata` | No | Arbitrary metadata for auditing |

**Authorization logic:**

```
effective_dsal (computed by RiskPipeline)
  ≤ agent.granted_dsal
  AND decision_type ∈ agent.allowed_decision_types
→ authorized
```

---

## Complete Example

```yaml
decision_policy:
  remediation:          1
  configuration_change: 2
  data_access:          1
  network_action:       3
  delegation:           3
  policy_update:        4
  # custom:
  db_migration:         3

capability_matrix:
  data_access:
    operations: [http_get, read_file]
  configuration_change:
    operations: [http_post, http_put, write_file]
  remediation:
    operations: [run_command, http_post, write_file]
  network_action:
    operations: [http_get, http_post, http_put]
  delegation:
    operations: [http_post]
  policy_update:
    operations: [http_post, http_put, write_file]
  db_migration:
    operations: [http_post, write_file]

environment_rules:
  high_risk_keywords:
    - prod
    - production
    - live
    - prd
    - customer-data
    - main-cluster

authority_roles:
  0: "any-sre"
  1: "sre-on-call"
  2: "security-engineer"
  3: "ciso"
  4: "board-approval"

allow_unregistered_agents: false

agent_registry:

  ops-agent/v1:
    granted_dsal: 2
    allowed_decision_types:
      - remediation
      - configuration_change
      - data_access
    metadata:
      team: ops
      environment: production

  migration-agent/v1:
    granted_dsal: 3
    allowed_decision_types:
      - db_migration
    metadata:
      team: data-engineering
      environment: production
```

---

## Validation

Policy changes can be validated before deployment:

```bash
python -c "
from shani.authority.policy import DecisionPolicyProvider
p = DecisionPolicyProvider.from_yaml('policy/decision_policy.yaml')
print('decision types:', list(p._policy.keys()))
print('capability types:', p.capability_matrix.known_types())
print('agents:', list(p._agents.keys()))
print('env keywords:', p.environment_rules)
"
```
