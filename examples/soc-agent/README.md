# SOC Agent — Automated Remediation with Shani Governance

This example demonstrates a Security Operations Center (SOC) autonomous
agent that automatically remediates security incidents, governed by Shani.

## Scenario

A SOC agent continuously monitors security signals (SIEM, EDR, threat
intel) and proposes remediation actions. Shani evaluates each proposed
action against the agent's authority level, risk pipeline, and current
DIS (Decision Integrity State):

- **Low risk** (isolated host, reversible): Auto-approved at D-SAL 1
- **Medium risk** (production, limited blast): D-SAL 2, may trigger HITL
- **High risk** (critical blast, irreversible): Hard-denied regardless of evidence

## Architecture

```
Security Signals (SIEM / EDR / Threat Intel)
    │
    ▼
SOC Agent (LLM + tool calls)
    │  DecisionProposal
    ▼
Shani Evaluator ──── DISIntegrityMonitor
    │                       │
    │  ADO or DeniedDecision │
    ▼                       ▼
Remediation Executor   Escalate to HITL
    │
    ▼
SOAR / Ticketing / Notification
```

## Files

| File | Description |
|---|---|
| `scenario.py` | End-to-end remediation workflow simulation |
| `soc_agent.py` | SOC agent class with Shani integration |

## Quick Start

```bash
pip install shani[core]
python scenario.py
```
