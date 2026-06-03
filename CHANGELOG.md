# Changelog

All notable changes to Shani are documented here.

---

## [0.4.0] — 2026-05

### Fix: Canonical JSON now enforces CJ-2 (no whitespace) — Phase 4 prerequisite

All canonical JSON serialization calls now use `separators=(',', ':')` to produce
compact form with no whitespace, as required by `spec/canonicalization.md` Rule CJ-2.
Affected: `shani/schemas/decision.py`, `shani/schemas/posture.py`,
`shani/core/evaluator.py`, `shani/crypto/signing.py`.

This is a **breaking change** for existing ADO signatures computed with v0.3.x.
All signature hashes will differ from those produced by the previous (spaced) form.
Cross-language implementations (Rust, Go, TypeScript) MUST use compact separators.

### Fix: `pyproject.toml` version synced to `0.4.0`

`pyproject.toml` was incorrectly set to `0.3.0` while `shani/__init__.py`
declared `__version__ = "0.4.0"`.

---

## [0.4.0-draft] — 2026-05 (Spec Draft)

### New: Binding Layer (spec/shani-v0.4.md §8)

Introduces a structural constraint layer that operates *before* RiskPipeline.
Addresses two failure modes identified in the Justification model:

- **Justification Theater** — high-throughput automation causes human judgment
  to evaporate while the approval record persists. The architecture confused
  justification-as-record with justification-as-decision.
- **Chain Dilution / Orphaned Intent** — in A→B→C→D agent chains, each node
  is correctly attributed but the composite action was authorized by no
  principal. Intent does not compose linearly.

### New concepts (normative)

**UserPosture** — a signed, persistent declaration by a principal defining
the boundary of actions they accept responsibility for. Distinct from
`agent_registry` configuration: it is a declaration document, not a setting.

```yaml
posture:
  target_scope:           "host:dev-*"
  max_blast_radius:       limited
  reversibility_required: true
  minimum_evidence:       2
```

**OrgPolicy.absolute_constraints** — organization-defined ceiling on what
any UserPosture may declare. Enforced at registration time and at
PostureEngine evaluation. Added to `policy.yaml` under `org_policy`.

**PostureEngine** — new pipeline stage inserted before RiskPipeline:

```
DecisionProposal
     ↓
PostureEngine
  Layer 1: Static Match  (deterministic, no LLM)
  Layer 2: Semantic Evaluation
     ↓ (PASS only)
RiskPipeline  (unchanged)
```

**PostureRefinementRequest** — third evaluation outcome alongside
`AuthorizedDecisionObject` and `DeniedDecision`. Returned when the current
UserPosture cannot determine whether a proposal is in scope. Requires the
principal to refine their Posture; resubmission before update is rejected.

**PostureSimulation** — pre-signing requirement. Applies a candidate Posture
to historical proposals and shows the principal what would be REJECTed,
PASSed, or AMBIGUOUS. Prevents Binding Theater (signing without understanding
operational consequences).

### New: ADO v5.1

Two fields added to `AuthorizedDecisionObject` for cross-organizational chains:

- `propagated_constraints: list[str]` — constraints inherited from the
  originating principal's UserPosture, cryptographically signed
- `origin_org: str` — identifier of the originating organization

Cross-org ADOs without `propagated_constraints` are treated as AMBIGUOUS
by the receiving Shani. Mutation of `propagated_constraints` breaks
signature verification.

### Cross-org policy

`OrgPolicy.cross_org_min_dsal` defaults to 4. All cross-organizational
transitions require Board-level (HITL) approval by default.

### Not yet implemented

PostureEngine, PostureSimulation, and ADO v5.1 are spec-only in this release.
Reference implementation is planned for v0.4.1.

---

## [0.3.0] — 2026-04

### Breaking Changes

- **`requested_dsal` removed from `DecisionProposal`** — Agents can no longer declare their own oversight level. Effective D-SAL is computed by `RiskPipeline` from proposal context (blast_radius, reversibility, environment, evidence quality, framing risk). This is the most important security change in v0.3.

- **`DecisionPolicyProvider` constructor** — New optional parameters: `capability_matrix`, `environment_rules`. Existing code using positional arguments may need updating.

- **`ExecutionBoundary` constructor** — New optional `capability_matrix` parameter. If not passed, it is resolved from the `gate` argument automatically.

- **`gate.py` `_build_request`** — `authority_map` dict removed. Authority role names now come from `authority_provider.resolve_authority()`. Hardcoded role names ("SOC-Analyst" etc.) still appear as defaults in `StaticAuthorityProvider` but are overridable.

### New: Risk Pipeline

Four independent components replace the previous `DSALCalculator`:

- **`EvidenceEvaluator`** (`shani/risk/evidence.py`) — Source trust classification (SYSTEM_SENSOR / VERIFIED_TOOL / AGENT_DERIVED / SELF_REPORTED). Multiplies raw confidence by trust level. Detects conflicting evidence and all-self-reported sets.

- **`RiskAssessor`** (`shani/risk/assessor.py`) — Multi-dimensional risk scoring (blast_radius, reversibility, environment, evidence, intent_clarity). Produces `RiskScore(aggregate, dimensions, flags)`. Does not reference D-SAL.

- **`RuleEngine`** (`shani/risk/rules.py`) — Hard rules evaluated before D-SAL mapping. Built-in rules: `policy_update_hardcoded_floor` (OVERRIDE D-SAL=4), `critical_irreversible_floor` (OVERRIDE D-SAL=4), `prod_network_insufficient_evidence` (DENY), `no_evidence_critical_deny` (DENY), `low_confidence_high_risk` (DENY). Custom rules via `RuleEngine(extra_rules=[...])`.

- **`DecisionSpaceAnalyzer`** (`shani/risk/decision_space.py`) — Framing attack detection. Raises `framing_risk_score` when alternatives are undeclared or lower-risk alternatives are rejected without explanation.

- **`DSALMapper`** (`shani/risk/dsal_mapper.py`) — Converts `risk_score` (0.0–1.0) to D-SAL (0–4) via configurable threshold table. `effective_dsal = max(base_dsal_from_policy, risk_based_dsal)`.

- **`RiskPipeline`** (`shani/risk/pipeline.py`) — Orchestrates all four components. Returns `PipelineResult` with full audit trail.

### New: Policy as Code

Three hardcoded mappings moved to `policy/decision_policy.yaml`:

- **`capability_matrix`** — DecisionType → allowed Capability operations. Previously `_DECISION_TYPE_OPS` in `capability.py`. Now in `DecisionPolicyProvider.capability_matrix` (a `CapabilityMatrix` instance). `ExecutionBoundary` receives it via dependency injection. Custom DecisionTypes can be added without code changes.

- **`environment_rules`** — High-risk target keywords. Previously `PROD_KEYWORDS` class variable in `DSALCalculator`. Now injected via `DSALCalculator(environment_rules=...)`. Organizations can add "customer-data", "pci", "main-cluster" etc. without code changes.

- **`authority_roles`** — D-SAL → human role name. Previously hardcoded `authority_map` dict in `gate.py`. Now resolved via `authority_provider.resolve_authority(dsal)`. Organizations can use "SRE", "CISO", "Board-Approval" etc. without code changes.

### New: DenialContext

`DeniedDecision` now carries full context:

```python
summary = denied.to_human_summary()  # JSON-serializable dict
# Contains: reason, risk_score, risk_breakdown, rules_triggered,
#           evidence_flags, framing_risk, proposal_snapshot
```

`DecisionBoundaryViolation` carries a `DenialContext` object with the same information. HITL channels can display this to humans so they understand why an agent was stopped.

### New: ExecutionBoundary (enforced boundary)

`Capability` objects can only be created via `ExecutionBoundary.issue_capability(ado, proposal)`. Direct `Capability()` construction raises `CapabilityError`. This ensures ADO verification (signature, proposal_hash, nonce, expiry) is always performed before execution.

### Documentation

- `spec/SPEC.md` — Rewritten as v0.3 normative specification (now `spec/shani-v0.4.md`)
- `docs/ARCHITECTURE.md` — System design overview and data flow
- `docs/THREAT_MODEL.md` — 12-threat catalog with mitigations and residual risk ratings (now `spec/threat-model.md`)
- `docs/POLICY_REFERENCE.md` — Complete `policy.yaml` field reference with examples

### Tests

- `tests/unit/test_evaluator.py` — Rewritten for v0.3 (no pytest, no `requested_dsal`)
- `tests/unit/test_crypto_integrity.py` — Rewritten for v0.3
- `tests/security/test_dsal_calculator.py` — Context-driven D-SAL modifier verification
- `tests/security/test_risk_pipeline.py` — 4-component pipeline integration tests
- `tests/security/test_oss_clarity.py` — DenialContext propagation and JSON serializability
- `tests/security/test_policy_as_code.py` — Verifies no hardcoded capability/environment/authority in code

### Examples

All scenarios rewritten for v0.3 API:
- `examples/remediation/scenario.py` — Basic proposal → ADO → execution
- `examples/delegation/scenario.py` — Orchestrator → specialist with escalation blocking
- `examples/dis_violation/scenario.py` — Replay attack → VIOLATED state → manual reset
- `examples/firewall_chain/scenario.py` — Risk levels and RuleEngine DENY/OVERRIDE

### CI

`.github/workflows/ci.yml` spec-check job verifies three policy-as-code invariants on every push:
1. `requested_dsal` absent from `DecisionProposal`
2. `_DECISION_TYPE_OPS` / `CapabilityMatrixLoader` absent from `capability.py`
3. `authority_map` hardcoded dict absent from `gate.py`

---

## [0.2.0] — 2026-03

- ADO v5 schema: `issued_at`/`expires_at` (replacing `authorized_at`/`valid_until`), `signature` (replacing `binding_hash`), `exec_context` grouping, `max_children` fan-out limit
- `proposal_hash`: SHA-256 of canonical proposal fields embedded in ADO
- `FileNonceStore`: persistent replay prevention across process restarts
- `DelegationRules`: `max_child_dsal < authorized_dsal` enforced as schema invariant
- LangGraph adapter: tool-level and node-level governance
- OpenClaw sidecar: HTTP-based governance for non-Python agents

## [0.1.0] — 2026-02

- Initial release
- `DecisionProposal` → `AuthorizedDecisionObject` flow
- `D-SAL` levels 0–4
- `StaticAuthorityProvider`, `YAMLAuthorityProvider`
- `DISStateMachine`: VALID / DEGRADED / VIOLATED
- `HITLGate` with callback, CLI, and webhook channels
- `InMemoryNonceStore`
- LangChain adapter
