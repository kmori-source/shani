# RFC-0001: PostureEngine Design

**Status:** Active
**Author(s):** Shani Working Group
**Created:** 2026-05
**Last updated:** 2026-05

---

## Summary

This RFC documents the design rationale, layer contract, and open questions for the PostureEngine introduced in Shani v0.4. The PostureEngine is a two-layer evaluation stage inserted before RiskPipeline that enforces a principal's declared `UserPosture` as a structural pre-filter. It is the primary mechanism implementing the "Binding" concept.

---

## Motivation

### The Justification Theater failure mode

In Shani v0.3, the primary governance primitive is the `Justification`: a record that an action was approved by a principal within a defined scope. Under normal usage this works well. Under high-throughput automation, a failure mode emerges:

- The system that produces justifications (the agent) is also the system whose actions are being justified.
- As volume increases, human approval becomes rubber-stamp approval.
- Accountability is nominal: someone approved, but without meaningful engagement.

The result is **Justification Theater**: the governance machinery is present and running, but the substance of authorization has migrated into the agent.

### Why pre-filtering is necessary

The existing v0.3 pipeline evaluates all proposals through RiskPipeline and then routes high-risk ones to HITL. This means every proposal, regardless of whether it falls within the principal's declared scope, reaches the evaluation pipeline. There is no structural mechanism that makes out-of-scope proposals **unreachable**.

The Binding Layer introduces such a mechanism. A principal declares, in advance and with their signature, the boundary of actions they accept responsibility for. The PostureEngine enforces this boundary structurally: proposals outside the boundary never reach RiskPipeline. They are rejected at the gate.

This shifts the governance problem from "did someone approve?" to "does this proposal fall within what the responsible principal said they accept responsibility for?" The latter question is answerable deterministically, without human judgment, at scale.

---

## Detailed Design

### Pipeline position

```
DecisionProposal
     ↓
PostureEngine           ← new in v0.4
     ↓ (PASS only)
RiskPipeline
     ↓
HITL / ADO issuance
```

The PostureEngine MUST be inserted before RiskPipeline. Proposals that fail PostureEngine MUST NOT reach RiskPipeline.

### Two-layer evaluation contract

The engine operates in two layers to separate deterministic structural checks from semantic evaluation.

#### Layer 1: Static Match

Layer 1 performs four deterministic comparisons against `UserPosture.constraints`:

| Check | Proposal field | Posture field | Comparison | Result on violation |
|---|---|---|---|---|
| Target scope | `proposal.target` | `constraints.target_scope` | Regex/glob match | REJECT |
| Blast radius | `proposal.blast_radius` | `constraints.max_blast_radius` | Enum ordering | REJECT |
| Reversibility | `proposal.reversibility` | `constraints.reversibility_required` | Boolean implication | REJECT |
| Evidence count | `len(proposal.evidence)` | `constraints.minimum_evidence` | Integer >= | REJECT |

**Blast radius ordering:** `isolated < limited < significant < critical`. A proposal with `significant` blast radius against a posture with `max_blast_radius: limited` is REJECT.

**Reversibility:** If `reversibility_required = true` and `proposal.reversibility = false`, the result is REJECT.

Layer 1 is deterministic: identical inputs MUST produce identical outputs. No LLM, no stochastic evaluation.

If all four checks pass: proceed to Layer 2.
If any check fails: return `PostureRejection` immediately. Do not call Layer 2.

**Rationale for short-circuiting:** Layer 1 failures are definitional, not ambiguous. A proposal with `blast_radius: critical` against a posture declaring `max_blast_radius: limited` is unambiguously outside scope. Calling Layer 2 would add latency and LLM cost without changing the outcome.

#### Layer 2: Semantic Evaluation

Layer 2 applies when Layer 1 yields PASS or AMBIGUOUS (future: Layer 1 may yield AMBIGUOUS for regex patterns that partially match).

Layer 2 MAY use:
- RiskPipeline outputs (risk_score, intent_clarity, framing_risk)
- Semantic similarity between `proposal.description` and `posture.intent_statement`
- Historical proposal patterns for this principal

Layer 2 MUST:
- Return PASS if the proposal is clearly within the posture's intent
- Return REJECT if the proposal is clearly outside the posture's intent
- Return AMBIGUOUS if the Layer 2 evaluation cannot determine scope
- Produce `PostureRefinementRequest` on AMBIGUOUS — never `DeniedDecision`

**The AMBIGUOUS/REJECT distinction:** Layer 2 MUST distinguish between "this proposal is outside the posture" (REJECT, no path to approval without posture update) and "this proposal may or may not be within the posture; the posture is insufficiently precise" (AMBIGUOUS, requires posture refinement). Conflating these produces two failure modes:
- Over-rejection (AMBIGUOUS treated as REJECT): legitimate proposals are blocked; principal refinement provides no path forward.
- Under-rejection (REJECT treated as AMBIGUOUS): out-of-scope proposals return a `PostureRefinementRequest`, teaching the agent what refinement would allow them through.

### PostureRefinementRequest as a first-class outcome

`PostureRefinementRequest` is not a subtype of `DeniedDecision`. It represents a different governance state:

| Outcome | Meaning | Agent behavior | Principal behavior |
|---|---|---|---|
| `DeniedDecision` | Proposal is outside policy. Denial is final. | Halt, do not retry | Review denial reason |
| `PostureRefinementRequest` | Posture cannot determine scope. Posture update required. | Halt, notify principal | Update posture, re-sign, resubmit is permitted |
| `AuthorizedDecisionObject` | Approved. Execute. | Execute, call register_executed | — |

### Principal workflow

```
1. Principal declares UserPosture (with PostureSimulation requirement)
2. Agent submits proposal
3. PostureEngine: Layer 1 → Layer 2 → PASS / REJECT / AMBIGUOUS
4a. REJECT → PostureRejection (logged; principal may update posture)
4b. AMBIGUOUS → PostureRefinementRequest → principal refines posture → resubmit
4c. PASS → RiskPipeline → HITL if needed → ADO issuance
```

### PostureSimulation pre-signing requirement

Before a principal can sign or update a `UserPosture`, the implementation MUST run `PostureSimulation`:

1. Apply the candidate posture to a representative sample of historical proposals (minimum: 30 days or 100 proposals, whichever is smaller).
2. Produce a `PostureSimulationResult`:
   - Counts: PASS, REJECT, AMBIGUOUS
   - At least 3 representative examples per category (if any exist)
   - Delta comparison with the current posture
3. Present the result to the principal before accepting the signing action.

The requirement prevents **Binding Theater**: a principal signing a posture without understanding what it structurally permits or denies.

---

## Conformance impact

New normative requirements (added to `spec/shani-v0.4.md §8.9`):

| Test | Expected behavior |
|---|---|
| Proposal with `blast_radius > posture.max_blast_radius` | Layer 1 REJECT; does not reach RiskPipeline |
| Proposal with `reversibility=false` when `reversibility_required=true` | Layer 1 REJECT |
| Proposal with `len(evidence) < minimum_evidence` | Layer 1 REJECT |
| Proposal with non-matching `target` | Layer 1 REJECT |
| Layer 2 AMBIGUOUS result | Returns `PostureRefinementRequest`, never `DeniedDecision` |
| Resubmission before posture update | Same `PostureRefinementRequest` |
| `UserPosture` without `simulation_ref` | Rejected at registration |
| `UserPosture` violating `OrgPolicy.absolute_constraints` | Rejected at registration |

---

## Alternatives considered

### Alternative A: Single-layer deterministic engine

Reject or pass based only on Layer 1 structural checks; no semantic evaluation.

**Rejected because:** Many real-world proposals have targets that match the scope pattern but are semantically outside the principal's intent (e.g., `host:dev-*` matches `host:dev-customer-data-42` which the principal did not intend to include). A purely structural engine produces false positives that erode principal trust.

### Alternative B: LLM-only engine

Delegate all posture evaluation to an LLM with the posture and proposal as context.

**Rejected because:** LLM evaluation is non-deterministic, latency-sensitive, and subject to the same manipulation as the proposals it evaluates. An adversarial agent could craft proposal descriptions to influence the LLM's posture evaluation. Structural checks are needed as a deterministic foundation.

### Alternative C: Merge PostureEngine into RiskPipeline

Add posture evaluation as a dimension within the existing risk_score computation.

**Rejected because:** Risk scoring produces a scalar value that collapses the posture/risk distinction. A proposal can be high-risk and within posture, or low-risk and outside posture. These require different responses. Structural pre-filtering must happen before risk scoring — not as part of it.

---

## Open questions

- [ ] **Layer 1 AMBIGUOUS for partial regex matches:** Should a proposal where `target` partially matches `target_scope` (e.g., the pattern is a complex regex that matches some but not all components) produce Layer 1 AMBIGUOUS rather than passing to Layer 2? Current spec says Layer 1 is deterministic (binary pass/fail). This may be too restrictive for complex patterns.

- [ ] **Rate limiting on PostureRefinementRequest:** T15 (Ambiguity Escalation) identified that adversarial agents can use repeated AMBIGUOUS results to map the posture boundary. Rate limiting is RECOMMENDED but not yet normative. What is the appropriate rate limit? Per-proposal? Per-agent? Per-time-window?

- [ ] **PostureSimulation sample size:** The current requirement is "30 days or 100 proposals, whichever is smaller." Is this sufficient for organizations with low proposal volume (few historical proposals) or high proposal volume (100 proposals may be unrepresentative of the full distribution)?

- [ ] **Multi-principal posture:** The current design assigns one `UserPosture` per `principal_id`. For shared agents (where multiple principals share responsibility), posture composition rules are undefined. Which posture applies when an agent is authorized by two different principals?

---

## References

- [Shani Spec §8 (Binding Layer)](../spec/shani-v0.4.md)
- [Threat Model T13 (Posture Drift)](../spec/threat-model.md)
- [Threat Model T15 (Ambiguity Escalation)](../spec/threat-model.md)
- [RFC-0002: Propagated Constraints](RFC-0002-propagated-constraints.md)
