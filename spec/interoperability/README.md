# Shani Interoperability

This directory contains profiles and requirements for interoperability between Shani implementations across different languages, organizations, and runtime environments.

## Contents

| File | Description |
|---|---|
| `conformance-profile.md` | Minimum requirements for a "Shani-compatible" implementation |
| `cross-org-protocol.md` | Protocol for cross-organizational ADO exchange |

## Interoperability Levels

A Shani implementation declares which interoperability level it supports:

| Level | Name | Requirements |
|---|---|---|
| L1 | **Schema-compatible** | Produces and consumes JSON matching `spec/ado-schema.json` and `spec/proposal-schema.json` |
| L2 | **Signature-compatible** | L1 + produces signatures verifiable by other L2 implementations using `spec/canonicalization.md` |
| L3 | **Posture-compatible** | L2 + implements PostureEngine and can validate `propagated_constraints` from foreign ADOs |

The reference Python implementation targets L3. New language implementations SHOULD target at least L2.

## Cross-Implementation Verification

An ADO produced by implementation A is verifiable by implementation B if and only if:
1. Both implement the same canonical JSON rules (`spec/canonicalization.md`)
2. B has access to A's authority public key
3. The ADO has not expired

See `cross-org-protocol.md` for the full verification protocol across organizational boundaries.
