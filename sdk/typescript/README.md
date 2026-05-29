# @shani/sdk — TypeScript SDK

TypeScript SDK for the Shani Decision Governance Layer (spec v0.4).

## Status

🚧 **Skeleton** — Core types, evaluator, DIS state machine, and execution
boundary implemented. No external dependencies (uses Node.js built-ins only).

## Installation

```bash
npm install @shani/sdk
```

## Quick Start

```typescript
import { ShaniEvaluator, createProposal, ExecutionBoundary } from "@shani/sdk";

const evaluator = new ShaniEvaluator({ maxAuthorizedDsal: 2 });

const proposal = createProposal({
  decision_type: "remediation",
  proposed_by: "agent-1",
  intent: "restart service svc-api due to memory leak",
  reversibility: "reversible",
  blast_radius: "limited",
});

const result = evaluator.evaluate(proposal);

if (result.authorized) {
  console.log("ADO issued:", result.ado.decision_id);

  const boundary = new ExecutionBoundary(evaluator);
  const cap = boundary.issueCapability(result.ado);

  cap.execute((ado) => {
    console.log("Executing with authority:", ado.authority);
  });
} else {
  console.log("Denied:", result.denial.reason);
}
```

## DIS State Machine

```typescript
const evaluator = new ShaniEvaluator();
const dis = evaluator.disStateMachine;

// Escalate to DEGRADED
dis.transition("DEGRADED", "assumption drift detected", "shani-monitor");

// Proposals now denied — DIS is not VALID
const result = evaluator.evaluate(proposal);
// result.authorized === false

// Manual reset from VIOLATED (requires justification + human authority)
dis.resetToValid("root cause resolved", "ops-lead@example.com");
```

## Architecture

```
createProposal()
    │
    ▼
ShaniEvaluator.evaluate()           src/evaluator.ts
    │  • DIS check (SPEC §4.4)
    │  • D-SAL ceiling check (SPEC §4.3)
    │  • HMAC-SHA256 signature (SPEC §4.6)
    │
    ▼ EvaluationResult { authorized: true, ado }
    │
    ▼
ExecutionBoundary.issueCapability()  src/boundary.ts
    │  • verifyAdo() — signature + expiry
    │  • registerExecuted() — nonce consumption
    │
    ▼
Capability.execute((ado) => { ... })
```

## Building

```bash
npm install
npm run build
npm test
```

## Requirements

- Node.js >= 18.0.0
- No external runtime dependencies (crypto uses Node.js built-ins)

## Spec Conformance

Normative requirements: [`spec/shani-v0.4.md`](../../spec/shani-v0.4.md)
