# Shani Runtime — Rust

Rust implementation of the Shani Decision Governance Layer (spec v0.4).

## Status

🚧 **Skeleton** — Core types and evaluator implemented. Conformance test
integration and production hardening in progress.

## Architecture

```
DecisionProposal
    │
    ▼
ShaniEvaluator::evaluate()          src/evaluator.rs
    │  • DIS state check (SPEC §4.4)
    │  • D-SAL ceiling check (SPEC §4.3)
    │  • HMAC-SHA256 signature (SPEC §4.6)
    │
    ▼
AuthorizedDecisionObject (ADO v5)
    │
    ▼
ExecutionBoundary::issue_capability()   src/boundary.rs
    │  • verify_ado() — signature + expiry
    │  • register_executed() — nonce consumption (replay prevention)
    │
    ▼
Capability::execute(|ado| { ... })
```

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
shani-runtime = { path = "../runtime/rust" }
```

```rust
use shani_runtime::{ShaniEvaluator, DecisionProposal, DecisionType, BlastRadius, EvaluationResult};

let mut evaluator = ShaniEvaluator::builder()
    .max_authorized_dsal(2)
    .build();

let proposal = DecisionProposal::builder()
    .decision_type(DecisionType::Remediation)
    .proposed_by("agent-1")
    .intent("restart service svc-api")
    .blast_radius(BlastRadius::Limited)
    .reversible(true)
    .build();

match evaluator.evaluate(&proposal) {
    EvaluationResult::Authorized(ado) => println!("ADO: {}", ado.decision_id),
    EvaluationResult::Denied(d) => println!("Denied: {}", d.reason),
}
```

## Building

```bash
cargo build
cargo test
cargo run --example basic_evaluation
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `hmac-signing` | ✅ | HMAC-SHA256 signing (minimum per SPEC §4.6) |
| `ed25519` | — | Ed25519 signing (recommended for production) |

## Spec Conformance

All implementations must satisfy the normative requirements in
[`spec/shani-v0.4.md`](../../spec/shani-v0.4.md).

Key invariants:
- No ADO → no Capability → no execution
- DIS `VIOLATED` → all proposals denied
- Nonce consumed on execution (replay prevention)
- `max_child_dsal < authorized_dsal` (escalation prevention)
