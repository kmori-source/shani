# Shani Runtime — Go

Go implementation of the Shani Decision Governance Layer (spec v0.4).

## Status

🚧 **Skeleton** — Core types, evaluator, DIS state machine, and execution
boundary implemented. Conformance test integration in progress.

## Architecture

```
DecisionProposal
    │
    ▼
ShaniEvaluator.Evaluate()           evaluator.go
    │  • DIS state check (SPEC §4.4)
    │  • D-SAL ceiling check (SPEC §4.3)
    │  • HMAC-SHA256 signature (SPEC §4.6)
    │
    ▼
AuthorizedDecisionObject (ADO v5)
    │
    ▼
ExecutionBoundary.IssueCapability()  boundary.go
    │  • VerifyADO() — signature + expiry
    │  • RegisterExecuted() — nonce consumption
    │
    ▼
Capability.Execute(func(*ADO) error)
```

## Usage

```go
import shani "github.com/kmori-source/shani/runtime/go"

evaluator := shani.NewShaniEvaluator(shani.DefaultAuthorityConfig())

proposal := shani.NewProposal(
    shani.DecisionTypeRemediation,
    "agent-1",
    "restart service svc-api",
    shani.BlastRadiusLimited,
    true,
)

ado, denied := evaluator.Evaluate(proposal)
if denied != nil {
    log.Printf("denied: %s", denied.Reason)
    return
}

boundary := shani.NewExecutionBoundary(evaluator)
cap, err := boundary.IssueCapability(ado)
if err != nil {
    log.Fatal(err)
}

cap.Execute(func(ado *shani.AuthorizedDecisionObject) error {
    log.Printf("executing with authority: %s", ado.Authority)
    return nil
})
```

## Building

```bash
go build ./...
go test ./...
```

## Spec Conformance

Normative requirements: [`spec/shani-v0.4.md`](../../spec/shani-v0.4.md)

Key invariants:
- No ADO → no Capability → no execution
- DIS `VIOLATED` → all proposals denied
- Nonce consumed on execution (replay prevention)
- `max_child_dsal < authorized_dsal` (escalation prevention)
