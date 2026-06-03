# Contributing to Shani

Thank you for your interest in contributing. Before opening a pull request, read this document in full. It is short. It is not optional.

> **Please open an issue before submitting a PR.** This project is at an early stage and the design is still evolving. An issue lets us align on approach before you invest time in implementation.

---

## What Shani is

Shani is a **decision governance layer**. Its job is to enforce a boundary between an autonomous agent's intent and real-world consequence.

Shani evaluates. It does not plan, optimize, or execute.

---

## What Shani is not

This is not a list of missing features. This is a design constraint.

| Shani is NOT | Why |
|---|---|
| An agent planner | Agents plan. Shani governs the plans. |
| A security scanner | Shani governs decisions, not packets or code. |
| A replacement for authn/authz | Network-level controls are out of scope. |
| An LLM wrapper | The LLM produces proposals. Shani evaluates them. |

If your contribution makes Shani into any of these things, it will not be merged.

---

## The Frozen Vocabulary

These terms have precise meanings. Use them correctly in code, docs, and PRs.

| Term | Meaning |
|---|---|
| `DecisionProposal` | What an agent submits. Not a request. Not a command. A proposal. |
| `ADO` | What Shani issues. The only token an agent may act on. |
| `Capability` | What an ADO unlocks via ExecutionBoundary. Scoped and one-time. |
| `D-SAL` | Governance intensity (0–4). **Computed by Shani. Never declared by agents.** |
| `risk_score` | Continuous risk measure (0.0–1.0). Independent of D-SAL. |
| `effective_dsal` | The D-SAL actually applied. Output of RiskPipeline. |
| `DIS` | Decision Integrity State. VALID / DEGRADED / VIOLATED. |
| `HITL` | Human-in-the-Loop. A pause for human approval. |

---

## Design Invariants

These invariants are non-negotiable. PRs that break any of them will not be merged.

**1. Agents do not declare their own D-SAL.**  
`requested_dsal` was removed in v0.3. `effective_dsal` is computed by `RiskPipeline` from proposal context. Any PR that reintroduces agent-declared oversight levels violates the governance model.

**2. Policy lives in policy.yaml, not in code.**  
The following MUST NOT be hardcoded in Python:
- Capability matrix (which operations each DecisionType allows)
- Environment keywords (what counts as a production target)
- Authority role names (who approves at each D-SAL level)

All three are defined in `policy/decision_policy.yaml`. Code reads them via `DecisionPolicyProvider`.

**3. No ADO → no Capability → no execution.**  
`ExecutionBoundary.issue_capability(ado, proposal)` is the only path to a `Capability`. Every call verifies signature, proposal_hash, nonce, and expiry. There is no bypass.

**4. Denial always carries context.**  
Every `DeniedDecision` MUST carry `pipeline_result` and `proposal` so that `to_human_summary()` can explain the denial to a human. Silent denials undermine the justification requirement.

**5. risk_score and D-SAL are separate.**  
`RiskScore` does not contain a D-SAL field. `DSALMapper` converts between them using a configurable threshold table. Do not conflate the two.

---

## Spec First

The normative specification is at `spec/shani-v0.4.md`. It takes precedence over the implementation.

If you find a discrepancy between the spec and the code, the spec is right. Open a PR to fix the code, not the spec (unless the spec itself is wrong — that's a separate RFC).

---

## Submitting Changes

### Philosophy check (required for all PRs)

Before opening a PR, answer these questions:

- [ ] Does this change make Shani into a planner, optimizer, or executor?
- [ ] Does this add hardcoded policy (keywords, role names, capability mappings) to Python code?
- [ ] Does this allow agents to influence their own D-SAL?
- [ ] Does this remove DenialContext from any denial path?
- [ ] Does this break any conformance requirement in spec/shani-v0.4.md?

If any answer is "yes", reconsider the approach.

### Tests (required)

All changes must include tests.

```bash
# Zero-dependency check
shani check

# Full test suite
pytest
```

New security-relevant behavior must be tested in `tests/security/`. New evaluator behavior in `tests/unit/`.

### For new DecisionTypes

Do not add new DecisionTypes to the Python code. Add them to `policy/decision_policy.yaml`:

```yaml
decision_policy:
  my_new_type: 2

capability_matrix:
  my_new_type:
    operations: [http_get, http_post]
    note: "What this type is for"
```

Then add a test verifying the type is recognized and the capability matrix is correct.

---

## RFC Process

Significant changes (new components, changes to the ADO schema, changes to the risk pipeline) require an RFC.

Use the GitHub issue template: `.github/ISSUE_TEMPLATE/rfc.yml`

An RFC must answer:
1. What problem does this solve?
2. Does it contradict any design invariant above?
3. What is the threat model impact?
4. Can it be done via policy.yaml instead of code?

---

## Code Style

- Python 3.11+, type-annotated
- No hardcoded policy in `shani/` (see Design Invariants)
- Docstrings explain *why*, not just *what*
- Failing tests are preferable to no tests

---

## License

Apache 2.0. By contributing, you agree your contributions are licensed under the same terms.
