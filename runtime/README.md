# Shani Runtime Implementations

This directory contains native runtime implementations of the Shani Decision
Governance Layer for performance-critical agent execution environments.

| Implementation | Language | Status | Directory |
|----------------|----------|--------|-----------|
| Rust | Rust 1.75+ | 🚧 Skeleton | `rust/` |
| Go | Go 1.22+ | 🚧 Skeleton | `go/` |

## Python Reference

The normative Python implementation is in [`shani/`](../shani/) at the
repository root. See [`reference/python/`](../reference/python/) for
architecture documentation and module map.

## Conformance

All runtime implementations must satisfy the normative requirements in
[`spec/shani-v0.4.md`](../spec/shani-v0.4.md) and pass the conformance
test vectors in [`tests/conformance/`](../tests/conformance/).
