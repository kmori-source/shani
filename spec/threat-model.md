# Shani Threat Model

**Status:** Normative
**Version:** v0.4
**Supersedes:** `docs/THREAT_MODEL.md`

## Scope

This document covers threats to the **decision governance layer** — the boundary between an agent's intent and its execution. It does not cover threats to the underlying LLM, the network, or the operating system.

---

## Trust Boundary

```
UNTRUSTED                    │ SHANI BOUNDARY              │ TRUSTED
                             │                             │
Agent (LLM output)           │  ShaniEvaluator             │  World
  └─ DecisionProposal ──────►│  ExecutionBoundary          │
                             │  NonceStore                 │◄── Capability ops
Human (via HITL)             │  DIS monitor                │
  └─ approve/deny ──────────►│                             │
                             │                             │
Policy (YAML)                │                             │
  └─ capability_matrix ─────►│                             │
  └─ environment_rules ─────►│                             │
  └─ authority_roles ────────►│                             │
```

Agents are untrusted. Their proposals are evaluated, not accepted.

---

## Threat Catalog

### T1 — Fake ADO

**Description:** Agent constructs a valid-looking ADO without going through Shani (e.g., copies fields from a previous legitimate ADO, changes the target).

**Mitigation:**
- `proposal_hash` embeds SHA-256 of the proposal. Without the original proposal, the hash cannot be reproduced.
- `signature` covers `proposal_hash`. Altering proposal_hash invalidates the signature.
- `ExecutionBoundary.issue_capability()` verifies both.

**Residual risk:** None if verify_binding is called before every execution.

---

### T2 — Replay Attack

**Description:** Agent reuses a valid ADO from a previous execution.

**Mitigation:**
- `nonce` is a 32-byte random token embedded in the signature.
- `NonceStore.consume()` is called atomically on first execution.
- Subsequent calls with the same nonce are rejected.
- `FileNonceStore` persists across process restarts.

**Residual risk:** None with FileNonceStore. InMemoryNonceStore is vulnerable to process restart — use only in development.

---

### T3 — D-SAL Escalation via Proposal

**Description:** Agent sets `requested_dsal=0` to bypass oversight.

**Mitigation:**
- `requested_dsal` field does not exist in DecisionProposal (removed in v0.3).
- Effective D-SAL is computed by RiskPipeline from proposal context.
- Agent cannot influence its own oversight level.

**Residual risk:** None.

---

### T4 — Recursive Privilege Escalation (Delegation Chain)

**Description:** Agent A (D-SAL 3) delegates to B, which delegates to C, accumulating authority beyond the original grant.

**Mitigation:**
- `delegation_rules.max_child_dsal` is enforced: child's effective D-SAL must be strictly less than parent's `authorized_dsal`.
- This invariant is enforced at ADO schema construction — the object cannot be created in violation.
- `max_depth` limits recursion depth.
- `max_children` limits fan-out (bounded descendants = auditable scope).

**Residual risk:** None if schema invariants are enforced.

---

### T5 — Fan-Out Attack

**Description:** Agent with one D-SAL 3 ADO spawns 1000 child agents, each with D-SAL 2 ADOs, multiplying impact beyond what the authority intended.

**Mitigation:**
- `delegation_rules.max_children` limits the number of direct children per ADO.
- `delegation_rules.max_depth` limits recursion.
- Total descendants ≤ `max_children ^ max_depth` (auditable and bounded).

**Residual risk:** Low if max_children is set conservatively.

---

### T6 — Execution Drift

**Description:** Agent gets approval for "isolate host A" but executes "delete cluster". The ADO is valid, but the action differs from what was approved.

**Mitigation:**
- `exec_context` (including `intent_binding.target`, `intent_binding.intent`, `decision_type`) is included in the canonical signature payload.
- Altering any exec_context field invalidates the signature.
- Capability operations are constrained to `target_prefix` from `ado.intent_binding.target`.

**Residual risk:** None if ExecutionBoundary is used for all operations.

---

### T7 — Framing Attack

**Description:** Agent describes a high-risk action using low-risk language ("minor config update") to reduce oversight. Or agent selects the highest-privilege tool when a lower-privilege alternative exists.

**Mitigation:**
- `DecisionSpaceAnalyzer` detects absence of alternatives and unexplained rejection of lower-risk alternatives.
- `framing_risk_score` increases the final risk_score aggregate, potentially raising effective D-SAL.
- `intent_clarity` dimension in RiskAssessor penalizes vague descriptions.

**Residual risk:** Medium. Framing detection is heuristic. Agents can craft specific, detailed descriptions to reduce clarity penalty. Human review of high-risk proposals is the primary defense.

---

### T8 — Self-Reported Evidence Manipulation

**Description:** Agent fabricates its own evidence ("I checked and it's safe") with high confidence values to reduce risk_score.

**Mitigation:**
- `EvidenceEvaluator` classifies source trust. SELF_REPORTED sources have multiplier 0.35.
- All-SELF_REPORTED evidence sets have quality_score halved.
- `all_self_reported` flag is emitted and visible in DenialContext.

**Residual risk:** Medium. Agent can claim a trusted source name. Verification of source authenticity is out of scope for the governance layer.

---

### T9 — Capability Hardcode Bypass

**Description:** Developer hardcodes capability mappings in application code, allowing operations that policy.yaml does not permit, without changing policy.yaml.

**Mitigation:**
- `CapabilityMatrix` is owned by `DecisionPolicyProvider` (policy module), not by `ExecutionBoundary` (boundary module).
- `ExecutionBoundary` receives the capability_matrix via dependency injection.
- Conformance test verifies no hardcoded operations exist in boundary code.

**Residual risk:** Low. Requires intentional developer action to bypass. OSS transparency makes bypasses visible.

---

### T10 — Authority Role Confusion

**Description:** HITL notification shows the wrong role name, causing the wrong person to approve (or the right person to ignore).

**Mitigation:**
- Authority role names come from `authority_provider.resolve_authority()`.
- `authority_roles` section in policy.yaml maps D-SAL → role name.
- No hardcoded role names in gate.py or HITL code.

**Residual risk:** Low. Requires misconfiguration of policy.yaml.

---

### T11 — Environment Keyword Blindspot

**Description:** Organization uses "main-cluster" or "customer-data" for critical resources, but Shani only recognizes "prod". Risk_score is underestimated.

**Mitigation:**
- `environment_rules.high_risk_keywords` in policy.yaml is user-configurable.
- DSALCalculator receives keywords via dependency injection.
- No hardcoded keyword list in application code.

**Residual risk:** Low. Requires user to configure their own keywords. Default list covers common patterns.

---

### T12 — DIS Integrity Bypass

**Description:** Agent exploits a DEGRADED or pre-VIOLATED DIS state to slip proposals through before the system reaches VIOLATED.

**Mitigation:**
- DEGRADED does not reduce scrutiny — proposals are still fully evaluated.
- VIOLATED immediately denies all proposals.
- Kill switch provides immediate VIOLATED equivalent via environment variable.

**Residual risk:** Low in VIOLATED state. DEGRADED state still requires full evaluation.

---

### T13 — Posture Drift

**Description:** A principal's declared `UserPosture` no longer reflects their actual intent because the operating environment has changed (new systems, new risk thresholds, organizational restructuring). Proposals that fall within the old Posture are automatically passed to RiskPipeline without human awareness that the constraint is now stale.

**Mitigation:**
- `UserPosture.history` is immutable: previous versions are preserved, making drift visible in audit.
- PostureSimulation is required before re-signing, forcing the principal to evaluate the current Posture against recent proposals.
- `PostureRefinementRequest` is returned when a proposal is structurally within Posture but semantically ambiguous, prompting posture review.

**Residual risk:** Medium. There is no automatic staleness detection. A principal who does not review their Posture over time will accumulate drift silently. This is a known open problem — see `spec/shani-v0.4.md §8.10`.

---

### T14 — Shadow Execution

**Description:** An agent executes a capability through a side channel that bypasses `ExecutionBoundary`. For example, by calling an API directly rather than through the capability abstraction, or by using a tool not registered in the capability matrix.

**Mitigation:**
- `ExecutionBoundary.issue_capability()` is the only authorized execution path.
- Capability operations are constrained to whitelisted types in `capability_matrix`.
- Conformance tests verify that no direct API calls exist in boundary code.
- The capability matrix is owned by policy (not by boundary), so additions require a policy change.

**Residual risk:** Medium. In the Python reference implementation, nothing prevents an agent from calling external APIs directly. The defense is architectural (execution path discipline) not enforcement. A hostile agent that has code execution can bypass the boundary. This is an inherent limitation of software governance of software agents.

---

### T15 — Ambiguity Escalation

**Description:** An agent deliberately constructs proposals with ambiguous scope or intent to force `AMBIGUOUS` PostureEngine results, triggering `PostureRefinementRequest` responses instead of firm denials. By accumulating refinement requests, the agent maps the Posture boundary and finds the narrowest path to approval.

**Mitigation:**
- `PostureRefinementRequest` does not contain the full PostureEngine evaluation result — only the `ambiguity` explanation and `matched_constraints`.
- The number of refinement requests per proposal is logged and visible to administrators.
- Rate limiting on `PostureRefinementRequest` responses is RECOMMENDED (not yet normative).

**Residual risk:** Medium. An adversarial agent with sufficient requests can approximate the Posture boundary. This is an open research problem. See RFC-0001 for the PostureEngine design rationale.

---

### T16 — Authority Spoofing

**Description:** An agent presents an ADO with a plausible `authority` string (e.g., "board@example.com") that was not actually issued by a legitimate Shani instance. The forged authority string passes string-based checks but the cryptographic signature is missing or invalid.

**Mitigation:**
- `signature` verification is REQUIRED before execution (§5 conformance requirement 3).
- A failed `verify_binding()` call MUST halt execution — there is no bypass path.
- The `authority` field is covered by the signature payload; a forged authority string changes the signed bytes and invalidates any legitimate signature.

**Residual risk:** None if signature verification is enforced. The residual risk is implementation failure to call `verify_binding()`.

---

### T17 — Stale Signature Replay

**Description:** An attacker captures a valid ADO (with valid signature and nonce, not yet executed) and replays it in a different context or at a later time, after the original proposal's operational context has changed.

**Mitigation:**
- `expires_at` is included in the signature payload and checked before execution.
- Short ADO lifetimes (recommended: minutes to hours, not days) reduce the replay window.
- `nonce` is consumed on first execution; replay after execution is blocked.
- `NonceStore` (FileNonceStore in production) persists nonce consumption across process restarts.

**Residual risk:** Low with short-lived ADOs. The window between issuance and execution is the residual risk window. A stolen ADO that has not yet been executed is valid until `expires_at`.

---

### T18 — Cross-Org Constraint Mismatch

**Description:** Organization Alpha issues an ADO with `propagated_constraints: ["target_scope:domestic-only"]`. Organization Delta's Shani instance does not recognize the `target_scope` vocabulary and treats the constraint as satisfied (PASS) rather than AMBIGUOUS. Delta's agent executes an international operation that Alpha's constraint was intended to prevent.

**Mitigation:**
- Spec §8.8 normative requirement: unrecognized `propagated_constraints` vocabulary MUST produce AMBIGUOUS, not PASS. Fail-closed is the required default.
- `cross_org_min_dsal` (default: 4) requires Board-level HITL for all cross-org ADOs, providing a human review gate even when constraint vocabulary is unknown.
- Cross-org ADO use cases SHOULD establish a shared constraint vocabulary via bilateral agreement before deployment.

**Residual risk:** Medium. The "shared constraint vocabulary" problem is unsolved at the protocol level — there is no standard registry. Until RFC-0002 or an equivalent standard is finalized, cross-org constraint interoperability depends on bilateral coordination. See `spec/shani-v0.4.md §8.10`.

---

### T19 — Approval Laundering

**Description:** An agent presents a sequence of individually-legitimate proposals, each approved in isolation, to construct a composite capability that no single approval would have granted. A common pattern: the agent obtains an ADO for a benign initial action, then cites the existence of that approval as implicit justification for a higher-risk follow-on proposal ("the first step was already approved"). Distinct from T7 (Framing), which is about mislabeling a single proposal; laundering relies on chaining legitimately-labeled proposals to manufacture cumulative authority.

**Mitigation:**
- Each ADO is scoped to a single `intent_binding` — there is no cross-ADO chaining mechanism in the protocol.
- `exec_context` (target, intent, decision_type) is signed; approval of one action does not imply approval of related actions.
- `audit_context.reason` is REQUIRED in proposals; reviewers SHOULD examine the chain of prior ADOs when evaluating follow-on requests.
- `PostureRefinementRequest` responses do not expose the full Posture boundary, limiting boundary-mapping via iterative probing.

**Residual risk:** Medium. Detecting laundering requires human reviewers to correlate the history of related ADOs, not just the current proposal. Automated cross-ADO correlation is not currently normative. This is a known open problem — cross-ADO lineage tracking is under consideration for a future RFC.

---

### T20 — Signature Stripping

**Description:** An agent presents an ADO with the `signature` field removed (absent or `null`) rather than forged. The attack exploits implementations that check signature *validity* only when the field is present, treating its absence as a skippable case rather than a verification failure. Distinct from T16 (Authority Spoofing), which forges a plausible authority string with an invalid signature; stripping removes the signature entirely.

**Mitigation:**
- ADO schema treats `signature` as a REQUIRED field; schema-level construction fails if absent.
- `verify_binding()` MUST check for the *presence* of the `signature` field before cryptographic verification; an absent or `null` signature MUST be treated as a verification failure, not as a skippable field.
- `ExecutionBoundary.issue_capability()` calls `verify_binding()` unconditionally — there is no "skip verification" flag or fallback path.

**Residual risk:** None if `verify_binding()` treats absent signature as failure. Residual risk is an implementation defect where `None`/`null` bypasses the verification branch rather than triggering it.

---

## Out of Scope

The following threats are explicitly out of scope for Shani:

| Threat | Why out of scope |
|---|---|
| LLM prompt injection | Affects the agent's decision-making, not the governance layer |
| Stolen signing keys | Key management is an infrastructure concern |
| Malicious policy.yaml | Governance of the policy itself is a meta-governance problem |
| Network-level attacks | Shani is not a network security layer |
| Physical access | Not an AI governance concern |

---

## Residual Risk Summary

| Threat | Severity | Residual Risk | Primary Defense |
|---|---|---|---|
| T1 Fake ADO | Critical | None | proposal_hash + signature |
| T2 Replay | Critical | None (with FileNonceStore) | nonce consumption |
| T3 D-SAL self-declaration | Critical | None | field removed |
| T4 Delegation escalation | High | None | schema invariant |
| T5 Fan-out | High | Low | max_children |
| T6 Execution drift | High | None | exec_context signed |
| T7 Framing | Medium | Medium | heuristic + human review |
| T8 Evidence fabrication | Medium | Medium | source trust multipliers |
| T9 Capability hardcode | Low | Low | policy injection |
| T10 Role confusion | Low | Low | authority_provider |
| T11 Environment blindspot | Low | Low | configurable keywords |
| T12 DIS bypass | Low | Low | kill switch |
| T13 Posture drift | Medium | Medium | PostureSimulation + history |
| T14 Shadow execution | Medium | Medium | execution path discipline |
| T15 Ambiguity escalation | Medium | Medium | request logging + rate limiting |
| T16 Authority spoofing | Critical | None (if verify enforced) | signature verification |
| T17 Stale replay | Low | Low | short ADO lifetimes + nonce |
| T18 Cross-org mismatch | Medium | Medium | fail-closed + cross_org_min_dsal |
| T19 Approval laundering | Medium | Medium | single-scope ADO + audit correlation |
| T20 Signature stripping | Critical | None (if verify enforced) | absent signature = failure |
