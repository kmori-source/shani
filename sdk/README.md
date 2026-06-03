# Shani SDK

Client SDKs for integrating Shani governance into agent applications.

| SDK | Language | Status | Directory |
|-----|----------|--------|-----------|
| Python SDK | Python 3.11+ | ✅ Complete | `shani/sdk/python/` (in main package) |
| TypeScript SDK | TypeScript / Node.js 18+ | 🚧 Skeleton | `typescript/` |
| Go SDK | Go 1.22+ | 🚧 Skeleton | `go/` |

## Python SDK

The Python SDK is part of the `shani` package:

```bash
pip install "shani[core]"
```

```python
from shani.sdk.python.adapters.generic import governed_tool
from shani.sdk.python.schemas.decision import DecisionProposal
```

See [`shani/sdk/python/`](../shani/sdk/python/) for details.

## TypeScript SDK

See [`typescript/README.md`](typescript/README.md).

## Go SDK

See [`go/README.md`](go/README.md).

## Conformance

All SDKs wrap the core evaluator and must pass the conformance test vectors
defined in [`tests/conformance/`](../tests/conformance/).
