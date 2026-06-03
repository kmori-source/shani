# Cross-Org Supply Chain — Propagated Constraints (SPEC §8.8)

This example demonstrates cross-organizational Shani governance for
supply chain scenarios: an agent in Org A takes an action that propagates
through to Org B's infrastructure, carrying the originating org's
posture constraints.

## Problem

In a software supply chain, actions taken by one org's agents can
affect another org's systems (e.g., a dependency release triggering
an automated update in downstream repos). Without cross-org constraints,
the receiving org has no way to validate whether the action is within
the originating org's security posture.

## Solution: `propagated_constraints`

When Org A issues an ADO for a cross-org action, Shani embeds the
originating org's `UserPosture` constraints as `propagated_constraints`
(signed into the ADO). When Org B receives the cross-org ADO, its
Shani evaluator validates incoming proposals against those constraints.

```
Org A (source)                    Org B (downstream)
─────────────────────────────     ──────────────────────────────
Agent A proposes supply           Agent B proposes to apply
chain action                      Org A's action locally
    │                                   │
    ▼                                   ▼
Shani A evaluates                 Shani B receives cross-org ADO
    │ UserPosture → propagated          │ propagated_constraints
    ▼ constraints embedded              ▼ validated by PostureEngine
    ADO (signed, cross-org) ──────────▶ Allow / Deny / Refinement
```

## Files

| File | Description |
|---|---|
| `scenario.py` | Two-org supply chain simulation |

## Quick Start

```bash
pip install shani[core]
python scenario.py
```

## SPEC Reference

- SPEC §8.8: Cross-org ADO fields (`origin_org`, `propagated_constraints`)
- SPEC §8.9: Empty `propagated_constraints` MUST be treated as AMBIGUOUS
- RFC-0002: Propagated Constraints design document
