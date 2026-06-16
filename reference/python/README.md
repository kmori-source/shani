# Shani Reference Implementation — Python

This directory contains the canonical Python reference implementation of the
Shani Decision Governance Layer (spec v0.4).

## Status

The Python reference implementation lives in [`shani/`](../../shani/) at the
repository root. This directory provides a reorganized view with explicit module
boundaries and cross-references to the normative spec.

## Module Map

| Module | Path | Spec Section |
|--------|------|--------------|
| Schemas (Decision, ADO) | `shani/schemas/decision.py` | §4.1, §4.2 |
| Schemas (State, DIS) | `shani/schemas/state.py` | §4.4 |
| Schemas (Posture) | `shani/schemas/posture.py` | §8.2 |
| Core Evaluator | `shani/core/evaluator.py` | §5 |
| DIS State Machine | `shani/schemas/state.py` | §4.4 |
| Risk Pipeline | `shani/risk/pipeline.py` | §6 |
| Posture Engine | `shani/posture/engine.py` | §8.4 |
| Crypto / Signing | `shani/crypto/signing.py` | §4.6 |
| Authority Providers | `shani/authority/provider.py` | §5.3 |
| Decision Boundary | `shani/boundary/hook.py` | §7 |
| Execution Boundary | `shani/boundary/capability.py` | §7.2 |
| HITL Gate | `shani/hitl/approval/gate.py` | §9 |
| Integrity Monitor | `shani/integrity/monitor.py` | §4.5 |
| CLI | `shani/cli/main.py` | — |

## Installation

```bash
pip install shani                    # core (stdlib only)
pip install "shani[core]"           # + pydantic + pyyaml (recommended)
pip install "shani[all]"            # everything
```

## Running the reference evaluation flow

```python
from shani.core.evaluator import ShaniEvaluator
from shani.schemas.decision import DecisionProposal, DecisionType, BlastRadius
from shani.authority.provider import StaticAuthorityProvider

authority = StaticAuthorityProvider(max_authorized_dsal=2)
evaluator = ShaniEvaluator(authority_provider=authority)

proposal = DecisionProposal(
    decision_type=DecisionType.REMEDIATION,
    proposed_by="agent-1",
    intent="restart service svc-api",
    reversibility="reversible",
    blast_radius=BlastRadius.LIMITED,
)

result = evaluator.evaluate(proposal)
```

## Conformance Tests

```bash
pytest tests/conformance/
```

See [`tests/conformance/`](../../tests/conformance/) for the full conformance
test suite and [`spec/shani-v0.4.md`](../../spec/shani-v0.4.md) for normative
requirements.

## Relationship to Other Implementations

This Python implementation is the normative reference. Implementations in other
languages must pass the same conformance test vectors defined in
[`tests/conformance/fixtures.py`](../../tests/conformance/fixtures.py).

| Implementation | Directory | Status |
|----------------|-----------|--------|
| Python (reference) | `shani/` | ✅ Complete |
| Rust runtime | `runtime/rust/` | 🚧 Skeleton |
| Go runtime | `runtime/go/` | 🚧 Skeleton |
| TypeScript SDK | `sdk/typescript/` | 🚧 Skeleton |
| Go SDK | `sdk/go/` | 🚧 Skeleton |
