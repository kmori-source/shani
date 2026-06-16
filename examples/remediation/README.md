# Reversible Remediation — Remove Overpermissive Firewall Rule

This example demonstrates the core Shani governance flow for a **reversible
remediation** action: a SOC agent proposes to remove an overpermissive AWS
security group rule, and Shani evaluates whether to authorize it.

## Scenario

A SOC agent detects an overpermissive inbound rule (`sg-0abc123`, port 0–65535
from `0.0.0.0/0`) added erroneously during a maintenance window. The agent
proposes its removal, attaching SIEM and CloudWatch evidence. Shani:

1. Computes the D-SAL from context (evidence confidence, blast radius,
   reversibility) — the agent does **not** declare its own D-SAL.
2. Issues an ADO (Authorized Decision Object) if authorized.
3. Binds the ADO to the proposal via `verify_binding` — preventing replay attacks.

## What This Shows

| Protocol Feature | Description |
|---|---|
| `DecisionType.REMEDIATION` | Typed remediation proposal |
| `EvidenceItem` | SIEM alert + CloudWatch evidence attached to proposal |
| D-SAL computed from context | Authority level derived from confidence/blast/reversibility |
| `verify_binding` | Cryptographic binding of ADO to proposal |
| `register_executed` + replay check | Replay prevention after execution |
| `DeniedDecision` | Denial path with `reason` and `risk_score` |

## Flow

```
SOC Agent
    │  DecisionProposal (type=REMEDIATION, reversible=True,
    │                    blast_radius=LIMITED, evidence=[siem, cw])
    ▼
Shani Evaluator ── StaticAuthorityProvider (max_dsal=2)
    │             ── DecisionPolicyProvider (agent_registry)
    │
    ├─ AUTHORIZED → ADO (signed) → verify_binding ✓
    │                            → register_executed
    │                            → replay attempt → False ✓
    └─ DENIED     → DeniedDecision (reason, risk_score)
```

## Files

| File | Description |
|---|---|
| `scenario.py` | End-to-end remediation authorization demo |

## Quick Start

```bash
pip install shani[core]
python scenario.py
```

## Expected Output

```
==========================================================
  Scenario: Remediation — remove overpermissive firewall rule
==========================================================

  [Agent] proposal=<id>  type=remediation
          target=aws:sg-0abc123  reversible=True
          evidence: 2 items

  [Shani] AUTHORIZED ✓
          authority:      ...
          authorized_dsal: 2
          proposal_hash:  <hash>...
          signature:      <sig>...
          verify_binding: True
          replay attempt: False (expected False)

  ✓ Firewall rule removal authorized and executed
```

## SPEC Reference

- SPEC §4: Decision Proposal schema (`DecisionProposal`, `EvidenceItem`)
- SPEC §5: D-SAL computation from context
- SPEC §6: ADO fields and cryptographic binding
- SPEC §7: Replay prevention via `register_executed`
