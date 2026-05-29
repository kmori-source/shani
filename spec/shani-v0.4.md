# Shani Specification v0.4

**Status:** Draft
**Type:** Normative
**This document takes precedence over implementation.**

| Field | Value |
|---|---|
| Version | 0.4 |
| ADO Version | v5 (with v5.1 cross-org, v5.2 signature chain) |
| Supersedes | v0.3 |
| Date | 2026-05 |

---

## Changelog

| Version | Changes |
|---|---|
| v0.4 | Binding Layer (PostureEngine, UserPosture, PostureRefinementRequest, cross-org propagated_constraints) |
| v0.3 | DIS state machine, delegation rules (max_children), Kill Switch |
| v0.2 | Evidence evaluator, RiskPipeline, D-SAL definitions |
| v0.1 | Initial draft: DecisionProposal, ADO, conformance requirements |

---

## 1. Purpose

This document defines the normative behavior of a Shani-compliant implementation.

A system that does not conform to this specification must not call itself Shani-compatible.

---

## 2. Scope

This specification covers:

- The Decision Proposal schema and its validation rules
- The Authorized Decision Object (ADO) schema and its validity constraints
- The D-SAL level definitions and authority requirements
- The DIS state machine: states, transitions, and input taxonomy
- The Binding mechanism: what must be signed and how
- The Kill Switch behavior
- Conformance requirements for Execution Agents
- The Binding Layer (v0.4): UserPosture, PostureEngine, PostureRefinementRequest
- Cross-organizational constraint propagation (v0.4)

This specification does not cover:

- How agents reason, plan, or produce proposals
- How humans configure authority mappings (implementation-defined)
- Specific cryptographic algorithm selection beyond minimum requirements

---

## 3. Normative vocabulary

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** are used as defined in RFC 2119.

---

## 4. Core concepts

### 4.1 Decision Proposal

A **Decision Proposal** is a structured request from an agent to Shani.

Normative requirements:
- A proposal MUST NOT be treated as authorization. It is a request only.
- A proposal MUST contain: `decision_id`, `decision_type`, `proposed_by`, `reversibility`, `blast_radius`.
- `decision_id` MUST be globally unique (UUID v4 RECOMMENDED).
- An agent MUST NOT declare its own D-SAL level. The effective D-SAL is computed by the Shani evaluator from `decision_type` and context. Allowing agents to declare `requested_dsal` creates a privilege self-escalation vector and is explicitly prohibited.
- An agent MUST NOT execute any action on the basis of a proposal alone.

See `spec/proposal-schema.json` for the normative JSON Schema.

### 4.2 Authorized Decision Object (ADO) v5

An **ADO** is the exclusive authorization artifact issued by a Shani-compliant evaluator.

ADO v5 canonical structure:

```
AuthorizedDecisionObject (v5.2)
 ├── decision_id          # identity: bound to proposal
 ├── proposal_hash        # integrity: SHA-256 of canonical proposal
 ├── signature            # cryptographic: Ed25519 chain hash
 │
 ├── authority            # authorization: who approved
 ├── authorized_dsal      # authorization: level granted (0–4)
 │
 ├── delegation_rules     # escalation prevention
 │    ├── allowed_sub_decisions
 │    ├── max_child_dsal
 │    ├── max_depth
 │    └── max_children
 │
 ├── nonce                # replay prevention: one-time 32-byte token
 │
 ├── issued_at            # temporal: when issued
 ├── expires_at           # temporal: when invalid
 │
 ├── exec_context         # execution metadata (in signed payload)
 │    ├── decision_type
 │    ├── intent_binding
 │    ├── parent_decision_id
 │    ├── constraints
 │    └── rollback_policy
 │
 ├── signature_chain      # v5.2: multi-principal signing (SHOULD)
 ├── propagated_constraints  # v5.1: cross-org constraints
 └── origin_org           # v5.1: originating organization
```

Changes from ADO v4:
- `authorized_at` → `issued_at` (naming clarity)
- `valid_until` → `expires_at` (naming consistency with proposal)
- `max_children` added to `DelegationRules` (fan-out attack prevention)
- `signature` replaces `binding_hash` (name reflects actual semantics)
- `exec_context` sub-object groups execution-metadata fields (v5.0)
- `propagated_constraints`, `origin_org` added (v5.1, cross-org)
- `signature_chain` added (v5.2, multi-principal)

Normative requirements:
- An Execution Agent MUST NOT execute any action without a valid ADO.
- An ADO MUST contain: `decision_id`, `authorized_dsal`, `authority`, `expires_at`, `signature`.
- An ADO MUST NOT be used after its `expires_at` timestamp.
- An ADO MUST NOT be reused. Each `decision_id` MAY be executed at most once.
- An ADO's `signature` MUST be verified before execution.
- An ADO MUST NOT be modified after issuance. Any modification invalidates the signature.

See `spec/ado-schema.json` for the normative JSON Schema.

### 4.3 D-SAL (Decision System Autonomy Level)

D-SAL defines the governance ceiling for a decision.

| Level | Name             | Minimum authority required      | Delegation permitted |
|-------|------------------|---------------------------------|----------------------|
| 0     | Proposal Only    | None (human executes manually)  | No                   |
| 1     | Bounded          | Operator-class                  | No                   |
| 2     | Supervised       | Lead-class                      | Yes                  |
| 3     | Policy-Governed  | Org-policy document             | Yes                  |
| 4     | Full Autonomy    | Board-level authorization       | Yes                  |

Normative requirements:
- A Shani evaluator MUST enforce a `max_authorized_dsal` ceiling.
- Proposals requesting `dsal > max_authorized_dsal` MUST be denied.
- Delegation requests at D-SAL < 2 MUST be denied.

### 4.4 DIS (Decision Integrity State)

DIS represents the integrity posture of the decision governance system.

```
VALID ──────► DEGRADED ──────► VIOLATED
  ▲               │
  └───────────────┘
        (VIOLATED → VALID: manual reset only)
```

**States:**

- `VALID`: All integrity signals are within tolerance. Normal operation.
- `DEGRADED`: One or more medium-severity signals received. Heightened scrutiny.
- `VIOLATED`: High or critical signal received. **All execution MUST be suspended.**

**Normative requirements:**
- When DIS is `VIOLATED`, a Shani evaluator MUST deny all proposals.
- When DIS is `DEGRADED`, a Shani evaluator MUST deny all proposals. (conservative default; implementations MAY relax with explicit policy)
- `VIOLATED → VALID` transition MUST require: non-empty justification string + named human authority.
- DIS transitions MUST be logged with: timestamp, from-state, to-state, reason, triggered_by.

### 4.5 DIS Input Taxonomy

The following are the only normative classes of DIS input signals:

| Signal Type           | Default Severity | Description |
|-----------------------|-----------------|-------------|
| `assumption_drift`    | MEDIUM          | A declared assumption is no longer true |
| `agent_identity_drift`| HIGH            | Agent identity cannot be verified       |
| `environment_change`  | MEDIUM          | Environment changed post-authorization  |
| `delegation_violation`| HIGH            | Authority chain broken or exceeded      |
| `replay_attack`       | CRITICAL        | Previously-used ADO submitted again     |

Severity → DIS transition mapping:
- LOW: Log only. No transition.
- MEDIUM: `VALID → DEGRADED` (if not already degraded or violated).
- HIGH: `* → VIOLATED`.
- CRITICAL: `* → VIOLATED` immediately.

### 4.6 Binding

An ADO's **Binding** is a cryptographic commitment to its content.

Normative requirements:
- The binding MUST cover: `decision_id`, `authorized_dsal`, `authority`, `expires_at`, `constraints`.
- Implementations MUST support at minimum: Ed25519 signatures (RECOMMENDED) or HMAC-SHA256 (minimum).
- For multi-agent deployments, a **signature chain** SHOULD be used.
- A signature chain MUST be ordered: `authority_signature → boundary_signature`.
- Agents MUST verify the binding before execution.
- A failed binding verification MUST cause execution to halt.

See `spec/canonicalization.md` for the canonical payload format.

### 4.7 Kill Switch

The Kill Switch is a mechanism to immediately suspend all decision authorization.

Normative requirements:
- A Shani evaluator MUST support a Kill Switch.
- When active, ALL proposals MUST be denied regardless of DIS state or D-SAL level.
- The Kill Switch MUST be activatable via: environment variable, configuration, and programmatic API.
- Deactivation MUST require: justification string + named human authority identifier.

---

## 5. Execution Agent conformance

An Execution Agent is conformant with this specification if it:

1. Submits only `DecisionProposal` objects to Shani (no side channels).
2. Does not execute any action without a valid, unexpired ADO.
3. Verifies the ADO `signature` before every execution.
4. Calls `register_executed(ado)` (passing the full ADO object) after every successful execution, to ensure nonce consumption and replay prevention.
5. Does not reuse ADOs.
6. Does not attempt to produce ADOs itself.
7. Respects all `constraints` in the ADO.

---

## 6. Non-conformant patterns

The following patterns indicate a non-conformant implementation:

- An agent that "falls back" to execution without an ADO under any condition.
- A system that treats ADO constraints as optional hints.
- A Shani evaluator that produces ADOs when DIS is `VIOLATED`.
- A binding mechanism that does not cover `expires_at` (enables time extension attacks).
- A DIS reset mechanism that does not require human authority.

---

## 7. Versioning

This specification follows Semantic Versioning.

- MAJOR: Breaking changes to schema or state machine semantics.
- MINOR: New normative requirements added in backward-compatible ways.
- PATCH: Clarifications, editorial corrections.

Implementations MUST declare which version of this specification they conform to.

---

## 8. Shani v0.4 — Binding Layer

> **Status:** Normative (as of v0.4).
> **Motivation:** The v0.3 Justification model captures the *form* of authorization but not its *substance*. Under high-throughput automation, human judgment migrates into the system that generates justifications. Accountability becomes nominal. v0.4 introduces a Binding Layer that constrains the action space *before* proposals reach the evaluation pipeline.

---

### 8.1 Definitions

**Justification (v0.3)**
A record that an action was approved by a principal within a defined scope. Operates *after* a proposal is submitted. Subject to Justification Theater under automation bias.

**Binding (v0.4)**
A persistent, signed declaration by a principal that defines the boundary of actions they accept responsibility for. Operates *before* a proposal reaches RiskPipeline. Actions outside the bound state do not reach the human for approval — they are structurally unreachable.

**UserPosture**
The structured expression of a principal's Binding. Declares the constraints within which an agent's proposals are considered within scope. Owned by the individual principal. Must be signed. Must remain within OrgPolicy absolute constraints.

**OrgPolicy absolute_constraints**
Organization-defined upper bounds on what any UserPosture may declare. Cannot be overridden by individual principals. Defined in `policy.yaml` under `org_policy.absolute_constraints`.

**PostureRefinementRequest**
A third evaluation outcome, distinct from `AuthorizedDecisionObject` and `DeniedDecision`. Returned when the current UserPosture cannot determine whether a proposal is within scope. Requires the principal to refine their Posture before the proposal may be resubmitted.

**PostureSimulation**
A pre-signing evaluation that applies a candidate UserPosture to historical proposals, showing the principal what would have been REJECTed, PASSed, or AMBIGUOUS under the new Posture. Required before a Posture may be signed.

---

### 8.2 UserPosture Schema

A conforming `UserPosture` MUST contain:

```yaml
posture:
  version:             string          # semver, e.g. "1.0"
  principal_id:        string          # identity of the declaring principal
  signed_at:           ISO8601         # timestamp of signature
  intent_statement:    string          # human-readable statement of delegation intent
  simulation_ref:      string          # reference to PostureSimulation result used at signing

  constraints:
    target_scope:           string     # regex or glob pattern, e.g. "host:dev-*"
    max_blast_radius:       enum       # isolated | limited | significant | critical
    reversibility_required: boolean    # if true, irreversible proposals are REJECTed
    minimum_evidence:       integer    # minimum evidence item count required
    # data_sensitivity_max: enum       # reserved for RiskAssessor v0.4 dimension
```

A `UserPosture` MUST NOT declare constraints that exceed `OrgPolicy.absolute_constraints`. A Shani implementation MUST validate this at registration time and MUST reject any `UserPosture` that violates it.

See `spec/posture-schema.json` for the normative JSON Schema.

---

### 8.3 OrgPolicy Absolute Constraints

`policy.yaml` MUST support an `org_policy` section:

```yaml
org_policy:
  absolute_constraints:
    max_blast_radius:       enum       # no UserPosture may exceed this
    cross_org_min_dsal:     integer    # minimum D-SAL for cross-organizational transitions
    prod_reversibility:     boolean    # if true, irreversible ops on prod targets are always denied
```

These constraints form the ceiling of all UserPostures in the organization. They are enforced at two points: at UserPosture registration, and at PostureEngine evaluation.

---

### 8.4 PostureEngine

A conforming v0.4 implementation MUST insert a `PostureEngine` stage *before* `RiskPipeline` in the evaluation pipeline.

```
DecisionProposal
     ↓
PostureEngine
  Layer 1: Static Match (structural field comparison)
    → REJECT:    proposal field outside UserPosture constraint → return PostureRejection
    → AMBIGUOUS: structural match insufficient → proceed to Layer 2
    → PASS:      all structural constraints satisfied → proceed to Layer 2
  Layer 2: Semantic Evaluation
    → REJECT:    proposal is semantically outside UserPosture → return PostureRejection
    → AMBIGUOUS: PostureEngine cannot determine scope → return PostureRefinementRequest
    → PASS:      proceed to RiskPipeline
     ↓ (PASS only)
RiskPipeline  (unchanged from v0.3)
     ↓
HITL / ADO issuance  (unchanged from v0.3)
```

**Layer 1 evaluation contract:**
- Compare `proposal.target` against `posture.constraints.target_scope` (pattern match)
- Compare `proposal.blast_radius` against `posture.constraints.max_blast_radius` (enum ordering)
- Compare `proposal.reversibility` against `posture.constraints.reversibility_required`
- Compare `len(proposal.evidence)` against `posture.constraints.minimum_evidence`
- Any constraint violation → REJECT (deterministic, no LLM)

**Layer 2 evaluation contract:**
- Applied only when Layer 1 yields PASS or AMBIGUOUS
- May use RiskPipeline outputs to assess semantic alignment with UserPosture intent
- MUST return AMBIGUOUS (not REJECT) when the proposal is not clearly outside scope
- AMBIGUOUS result MUST produce a `PostureRefinementRequest`, not a `DeniedDecision`

---

### 8.5 PostureRefinementRequest

`PostureRefinementRequest` is a first-class evaluation outcome. It is NOT a subtype of `DeniedDecision`.

A conforming implementation MUST produce a `PostureRefinementRequest` containing:

| Field | Type | Description |
|---|---|---|
| `proposal_id` | string | identity of the proposal that triggered refinement |
| `principal_id` | string | the Posture owner who must act |
| `ambiguity` | string | human-readable explanation of what could not be determined |
| `matched_constraints` | list[string] | constraints that were satisfied |
| `unresolved` | list[string] | constraints that could not be evaluated |
| `suggested_update` | string or null | if determinable, a suggestion for how to update the Posture |

**Expected agent behavior on receiving PostureRefinementRequest:**
1. Halt the proposed operation (same as DeniedDecision)
2. Notify the principal identified in `principal_id` via a separate channel (not HITL)
3. Do NOT retry the proposal until the principal has updated and re-signed their Posture
4. Log the request with full context for audit

**Expected principal behavior:**
1. Review the `ambiguity` explanation and `suggested_update`
2. Run `PostureSimulation` with the proposed Posture update
3. Update and re-sign the UserPosture if the simulation result is acceptable
4. The original proposal may then be resubmitted

---

### 8.6 PostureSimulation (Pre-Signing Requirement)

Before a principal signs or updates a UserPosture, a conforming implementation MUST:

1. Run the candidate Posture against a representative sample of historical proposals
2. Produce a `PostureSimulationResult` containing:
   - Count of proposals that would PASS, REJECT, and be AMBIGUOUS
   - Representative examples of each category (minimum 3 REJECT examples if any exist)
   - Comparison with the current Posture's results (delta view)
3. Present this result to the principal before the signing action

This requirement exists to prevent **Binding Theater**: the condition in which a principal signs a Posture declaration without understanding its operational consequences, replicating the cognitive failure of Justification Theater at the Binding layer.

---

### 8.7 agent_registry as Declaration Document

In v0.4, `agent_registry` entries that include a `binding` section are treated as signed declaration documents, not configuration.

```yaml
agent_registry:
  soc-agent/v1:
    granted_dsal: 2
    allowed_decision_types: [remediation, configuration_change]
    binding:
      version: "1.0"
      principal_id: "sarah@example.com"
      signed_at: "2026-05-01T09:00:00Z"
      intent_statement: "I delegate automated remediation to this agent for dev environments."
      simulation_ref: "sim-2026-05-01-a3f9"
      posture:
        target_scope:           "host:dev-*"
        max_blast_radius:       limited
        reversibility_required: true
        minimum_evidence:       2
      history:
        - version: "0.9"
          signed_at: "2026-04-01T10:00:00Z"
          note: "Initial declaration. Scope included staging."
```

A conforming implementation MUST:
- Require `signed_at` and `principal_id` for any `binding` entry
- Reject registration of a `binding` whose `posture` violates `OrgPolicy.absolute_constraints`
- Preserve `history` immutably — previous versions MUST NOT be deleted
- Require a new signing action for any change to `posture` constraints

---

### 8.8 Chain Dilution and Cross-Organizational Binding

#### Within a single organization

The existing `delegation_rules` mechanism (Section 4.3) handles intra-organizational chains. No changes required. `max_child_dsal < authorized_dsal` prevents privilege escalation.

#### Across organizational boundaries

v0.4 introduces `propagated_constraints` in the ADO to address cross-organizational Chain Dilution.

**ADO v5.1 additions:**

```
AuthorizedDecisionObject (v5.1)
  ...all v5.0 fields...
  propagated_constraints: list[string]   # constraints inherited from the originating principal
  origin_org:             string         # identifier of the originating organization
```

**Normative requirements for cross-org transitions:**

1. `cross_org_min_dsal` in `OrgPolicy` sets the minimum D-SAL for any cross-organizational ADO. Default MUST be 4 (Board-level, HITL required).

2. When issuing an ADO that will be used across organizational boundaries, the issuing Shani MUST embed `propagated_constraints` derived from the principal's `UserPosture`.

3. The receiving Shani MUST validate incoming `propagated_constraints` against its own `PostureEngine` before proceeding.

4. A receiving Shani that cannot validate `propagated_constraints` (e.g., unknown constraint vocabulary) MUST treat the ADO as AMBIGUOUS and return a `PostureRefinementRequest` to the originating principal.

5. `propagated_constraints` MUST be included in the ADO canonical signature payload. Mutation of these fields MUST break signature verification.

**The intent of this mechanism:**
When principal A at Alpha declares `target_scope: "domestic-only"`, this constraint propagates through the entire A→B→C→D chain. Delta's agent cannot execute an international shipment because Alpha's constraint, embedded in the ADO and cryptographically signed, makes that action unreachable — regardless of whether Beta, Gamma, or Delta have their own justifications.

---

### 8.9 Conformance Requirements for v0.4

A Shani v0.4 conformant implementation MUST pass all v0.3 conformance tests PLUS:

**Posture registration tests:**
- A `UserPosture` violating `OrgPolicy.absolute_constraints` MUST be rejected at registration
- A `UserPosture` without `simulation_ref` MUST be rejected at registration
- A `binding.history` entry MUST NOT be modifiable after creation

**PostureEngine tests:**
- A proposal outside `target_scope` MUST receive REJECT from Layer 1, never reach RiskPipeline
- A proposal inside all structural constraints MUST NOT receive REJECT from Layer 1
- An AMBIGUOUS result MUST produce `PostureRefinementRequest`, never `DeniedDecision`

**PostureRefinementRequest tests:**
- An agent receiving `PostureRefinementRequest` MUST halt execution
- Resubmission before Posture update MUST produce the same `PostureRefinementRequest`

**Cross-org tests:**
- A cross-org ADO without `propagated_constraints` MUST be treated as AMBIGUOUS by the receiving Shani
- Mutation of `propagated_constraints` MUST break ADO signature verification

---

### 8.10 What v0.4 Does Not Solve

Binding is the second floor. Three problems remain open and are deferred to future versions.

**The bound state itself can be wrong.** An organization that binds a principal to an incorrect Posture has relocated the accountability problem to the moment of Posture articulation. PostureSimulation reduces this risk but cannot eliminate it. The failure is now concentrated and deliberate rather than distributed and inadvertent — an improvement, but not a solution.

**Cross-organizational Posture interoperability.** `propagated_constraints` requires a shared vocabulary between originating and receiving organizations. No such standard exists. Until one emerges, cross-org constraints are evaluated on a best-effort basis; receiving implementations that do not recognize a constraint MUST default to AMBIGUOUS, not PASS.

**Open action spaces.** Binding presumes that consequential action categories can be defined in advance. This breaks down for genuinely exploratory or novel work. For these use cases, v0.3 Justification remains the appropriate primitive, with its known failure modes accepted as the cost of operating in undefined action space.
