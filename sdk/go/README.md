# shani/sdk/go — Go SDK

Go SDK for the Shani Decision Governance Layer (spec v0.4).

## Status

🚧 **Skeleton** — Full evaluator, DIS state machine, and execution boundary
implemented. Single-package design for easy embedding.

## Installation

```bash
go get github.com/kmori-source/shani/sdk/go
```

## Quick Start

```go
import (
    "context"
    "log"
    shani "github.com/kmori-source/shani/sdk/go"
)

client := shani.NewClient(shani.DefaultConfig())

proposal := shani.NewProposal(
    shani.DecisionTypeRemediation,
    "agent-1",
    "restart service svc-api due to memory leak",
    shani.BlastRadiusLimited,
    true,
)

err := client.EvaluateAndExecute(context.Background(), proposal, func(ado *shani.ADO) error {
    log.Printf("executing with authority: %s (D-SAL %d)", ado.Authority, ado.AuthorizedDSAL)
    return nil // perform the actual action here
})
if err != nil {
    log.Fatal(err)
}
```

## DIS Management

```go
dis := client.DIS()

// Signal integrity issue
dis.Transition(shani.DISViolated, "replay attack detected", "shani-monitor")

// Proposals now blocked
_, err := client.Evaluate(proposal) // returns error

// Manual recovery (requires justification + human authority)
dis.ResetToValid("root cause resolved", "ops-lead@example.com")
```

## Architecture

```
NewProposal()
    │
    ▼
Client.Evaluate()
    │  • DIS check (SPEC §4.4)
    │  • D-SAL ceiling check (SPEC §4.3)
    │  • HMAC-SHA256 signing (SPEC §4.6)
    │
    ▼ *ADO
    │
Client.EvaluateAndExecute()
    │  • VerifyADO() — signature + expiry
    │  • registerExecuted() — nonce consumption
    │  • action(ado) — runs only if all checks pass
    │
    ▼
World (side-effecting action)
```

## Building

```bash
go build ./...
go test ./...
```

## Spec Conformance

Normative requirements: [`spec/shani-v0.4.md`](../../spec/shani-v0.4.md)
