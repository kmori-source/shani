# Vulnerability Scan + Auto Remediation (Shani Governance)

Workflow implementation defined in Issue #154.

## Flow

```
Vulnerability detection (pip-audit)
  ↓
LangGraph agent — remediation proposal (DecisionProposal)
  ↓
Shani — Approval, HITL, ADO issuance
  ↓  D-SAL 0/1: Auto-approved
  ↓  D-SAL ≥ 2: SecOps-Lead HITL (CLIApprovalChannel or Webhook)
Execution (pip install --upgrade)
  ↓
audit.json — who approved, what was done (with ADO ID)
```

## Governance Design

### Severity → BlastRadius → D-SAL

| CVSS Score | Severity | BlastRadius | Base D-SAL | HITL Required? |
|-----------|----------|-------------|-----------|----------------|
| ≥ 9.0     | CRITICAL | significant | 1 (+risk) | Conditional    |
| 7.0–8.9   | HIGH     | limited     | 1         | No             |
| 4.0–6.9   | MEDIUM   | isolated    | 1         | No             |
| < 4.0     | LOW      | isolated    | 1         | No             |

`remediation` type Base D-SAL is 1 (see policy.yaml).  
Because `approval_required_at_dsal=2`, most patches are auto-approved without HITL.  
HITL is triggered only when the risk score rises to D-SAL ≥ 2, such as with CRITICAL + prod targets.

### Agent Registration

Registered in `policy/decision_policy.yaml`:

```yaml
vuln-remediation-agent/v1:
  granted_dsal: 2
  allowed_decision_types: [remediation]
```

## How to Run

```bash
cd examples/vuln-remediation

# Interactive HITL (manual approval)
python scenario.py

# Auto-approve for CI/cron
SHANI_HITL_AUTO=1 python scenario.py

# No execution, scan only (dry-run)
SHANI_DRY_RUN=1 python scenario.py

# Use LangGraph orchestration
USE_LANGGRAPH=1 python scenario.py

# Custom audit output path
AUDIT_OUTPUT=/tmp/audit.json python scenario.py
```

### Dependencies

```bash
pip install pip-audit                          # scanner (required)
pip install langgraph langchain-core           # when using LangGraph (optional)
```

## audit.json Format

```json
{
  "schema_version": "1",
  "run_at": "2026-06-10T01:00:00Z",
  "agent_id": "vuln-remediation-agent/v1",
  "mode": "auto",
  "summary": {
    "total": 3,
    "executed": 2,
    "denied": 0,
    "skipped": 1
  },
  "entries": [
    {
      "timestamp": "2026-06-10T01:00:05Z",
      "vuln_id": "PYSEC-2024-123",
      "package": "requests",
      "installed_version": "2.28.0",
      "fix_version": "2.32.0",
      "severity": "HIGH",
      "action": "executed",
      "proposal_id": "prop-abc123…",
      "ado_id": "ado-def456…",
      "approved_by": "SOC-Analyst",
      "detail": "OK: upgraded to 2.32.0"
    }
  ]
}
```

`action` values:

| Value      | Description                                              |
|------------|----------------------------------------------------------|
| `executed` | ADO issued → patch applied                               |
| `denied`   | Blocked by Shani (policy violation or HITL rejection)    |
| `skipped`  | No fix version available                                 |
| `dry-run`  | Unexecuted record when SHANI_DRY_RUN=1                   |

## GitHub Actions Workflow

> Add as `.github/workflows/vuln-remediation.yml`.  
> Manual trigger (`workflow_dispatch`) → enable `schedule` for cron in the future.

```yaml
name: Vulnerability Scan + Auto Remediation

on:
  workflow_dispatch:          # manual trigger
  # schedule:                 # uncomment to enable cron
  #   - cron: '0 2 * * 1'    # every Monday at 02:00 UTC

permissions:
  contents: read

jobs:
  vuln-remediation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install -e ".[langchain]"   # shani + langgraph
          pip install pip-audit

      - name: Run vulnerability remediation
        env:
          SHANI_HITL_AUTO: '1'           # auto-approve in CI
          SHANI_DRY_RUN: '0'             # actually apply patches
          AUDIT_OUTPUT: audit.json
        run: |
          python examples/vuln-remediation/scenario.py

      - name: Upload audit log
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vuln-remediation-audit-${{ github.run_id }}
          path: audit.json
          retention-days: 90
```

### Steps to Enable Cron

1. Uncomment the `schedule` section (e.g., every Monday at 02:00 UTC)
2. Verify behavior with `SHANI_DRY_RUN: '1'`, then switch to `'0'`
3. Adjust `AUDIT_OUTPUT` to match the artifact path if needed

## Architectural Decisions

- **`DecisionType.REMEDIATION`** is used (no new type needed; `remediation: 1` in policy.yaml applies directly)
- Wrapped with **HITLGate**, requiring human approval only at D-SAL ≥ 2 (most patches pass automatically)
- **`reversibility=True`** — `pip install` upgrades are reversible by pinning back to the previous version
- **LangGraph is optional** — with `USE_LANGGRAPH=0`, the same logic runs in a direct loop
- **Single write, not append** — `audit.json` is overwritten on each run (version-controlled via GitHub Actions artifacts)
