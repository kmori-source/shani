# GitHub Actions — Shani Governance Integration

This example shows how to integrate Shani into a CI/CD pipeline so that
autonomous agents (dependency updaters, release bots, security scanners)
cannot take high-risk actions (force-push, deploy to production, delete
resources) without policy-backed authorization.

## Architecture

```
GitHub Actions Workflow
  └─ Shani Action Step (shani-governance.yml)
       ├─ shani evaluate proposal.json     ← any agent step emits this
       ├─ ADO issued or proposal denied    ← Shani returns a structured decision
       └─ Downstream step reads ADO JSON   ← gated execution
```

## Files

| File | Description |
|---|---|
| `shani-governance.yml` | Reusable workflow that wraps Shani evaluation |
| `agent_step.py` | Example agent that emits a `proposal.json` and checks the ADO |
| `proposal.json` | Sample proposal for a production deployment |

## Quick Start

```bash
pip install shani[core]
python agent_step.py
```

## Usage in Your Workflow

```yaml
jobs:
  deploy:
    steps:
      - name: Agent proposes deployment
        run: python agent_step.py > proposal.json

      - name: Shani evaluates proposal
        run: |
          shani evaluate proposal.json --output json > ado.json
          # Exit code 0 = authorized, 2 = denied

      - name: Deploy (only if authorized)
        if: ${{ success() }}
        run: deploy.sh --ado ado.json
```
