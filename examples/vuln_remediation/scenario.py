"""
examples/vuln-remediation/scenario.py

Vulnerability Scan + Auto Remediation governed by Shani.

Flow:
  Detect vulnerabilities  (pip-audit)
    → LangGraph agent (remediation)
    → Shani (Approval・HITL・ADO)
    → 実行 (pip install --upgrade)
    → audit.json (Who approved?)

Run:
    python scenario.py                      # interactive HITL
    SHANI_HITL_AUTO=1 python scenario.py    # auto-approve (CI / cron)
    SHANI_DRY_RUN=1   python scenario.py    # scan only, no execution
    AUDIT_OUTPUT=/tmp/audit.json python scenario.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

# ---------------------------------------------------------------------------
# Optional pydantic shim (mirrors pattern from soc-agent / langgraph_hitl)
# ---------------------------------------------------------------------------
try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

    _s = _iu.spec_from_file_location(
        "_compat", str(_pl.Path(__file__).parent.parent.parent / "shani/_compat.py")
    )
    _m = _iu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    _sh = _t.ModuleType("pydantic")
    for _k in ("BaseModel", "Field", "field_validator", "model_validator"):
        setattr(_sh, _k, getattr(_m, _k))
    sys.modules["pydantic"] = _sh

import warnings

warnings.filterwarnings("ignore")

from shani import DeniedDecision, DecisionType, BlastRadius, ShaniEvaluator
from shani.authority.policy import DecisionPolicyProvider
from shani.authority.provider import StaticAuthorityProvider
from shani.hitl.approval.gate import HITLGate
from shani.hitl.channel.channels import CLIApprovalChannel, CallbackApprovalChannel
from shani.schemas.decision import DecisionProposal, EvidenceItem

_POLICY_PATH = Path(__file__).parent / "policy.yaml"
_AGENT_ID = "vuln-remediation-agent/v1"

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class VulnFinding:
    vuln_id: str
    package: str
    installed_version: str
    fix_version: str | None
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    description: str


@dataclass
class RemediationEntry:
    timestamp: str
    vuln_id: str
    package: str
    installed_version: str
    fix_version: str | None
    severity: str
    action: str  # executed / denied / skipped / dry-run
    proposal_id: str | None
    ado_id: str | None
    approved_by: str | None
    detail: str


# ---------------------------------------------------------------------------
# 1. Vulnerability scanner
# ---------------------------------------------------------------------------


def run_scan() -> list[VulnFinding]:
    """Run pip-audit and return findings sorted CRITICAL → LOW."""
    print("\n[scan] Running pip-audit…")
    try:
        proc = subprocess.run(
            ["pip-audit", "--format=json", "--skip-editable"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print("  pip-audit not found. Install with: pip install pip-audit")
        return []

    if proc.returncode > 1:
        print(f"  pip-audit error: {proc.stderr[:200]}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("  Could not parse pip-audit output")
        return []

    findings: list[VulnFinding] = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            fix_vers = vuln.get("fix_versions", [])
            findings.append(
                VulnFinding(
                    vuln_id=vuln["id"],
                    package=dep["name"],
                    installed_version=dep["version"],
                    fix_version=fix_vers[0] if fix_vers else None,
                    severity=_cvss_to_severity(vuln.get("cvss_score")),
                    description=vuln.get("description", "")[:300],
                )
            )

    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: _order.get(f.severity, 4))
    print(
        f"  {len(findings)} vulnerability finding(s) across {len(data.get('dependencies', []))} packages"
    )
    return findings


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "MEDIUM"  # conservative default when CVSS is unavailable
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# 2. Remediation proposal builder
# ---------------------------------------------------------------------------

# Severity → BlastRadius mapping.
# Package upgrades modify the filesystem and affect runtime behavior.
# Even MEDIUM findings warrant LIMITED blast radius (requires HITL at D-SAL >= 2).
_SEVERITY_BLAST: dict[str, BlastRadius] = {
    "CRITICAL": BlastRadius.CRITICAL,  # D-SAL 3-4, always requires HITL
    "HIGH": BlastRadius.SIGNIFICANT,  # D-SAL 2-3, requires HITL
    "MEDIUM": BlastRadius.LIMITED,  # D-SAL 2, requires HITL
    "LOW": BlastRadius.ISOLATED,  # D-SAL 1, auto-approved
}

def make_proposal(f: VulnFinding) -> DecisionProposal:
    return DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by=_AGENT_ID,
        description=(
            f"Upgrade {f.package} {f.installed_version} → {f.fix_version} "
            f"to fix {f.vuln_id} [{f.severity}]"
        ),
        target=f"package:{f.package}",
        blast_radius=_SEVERITY_BLAST[f.severity],
        reversibility=True,  # pip upgrades are reversible (can pin previous version)
        evidence=[
            EvidenceItem(
                source="pip-audit",
                content=f"{f.vuln_id}: {f.description}",
                confidence=0.95,
            )
        ],
        confidence=0.95,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=30),
    )


# ---------------------------------------------------------------------------
# 3. Executor
# ---------------------------------------------------------------------------


def apply_patch(f: VulnFinding, dry_run: bool = False) -> str:
    if not f.fix_version:
        return "SKIPPED: no fix version available"
    if dry_run:
        return f"DRY-RUN: would run pip install {f.package}=={f.fix_version}"
    try:
        proc = subprocess.run(
            ["pip", "install", f"{f.package}=={f.fix_version}"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return "FAILED: pip install timed out"
    return (
        f"OK: upgraded to {f.fix_version}"
        if proc.returncode == 0
        else f"FAILED: {proc.stderr[:150]}"
    )


# ---------------------------------------------------------------------------
# 4. Governance + remediation loop (called from both direct and LangGraph paths)
# ---------------------------------------------------------------------------


def remediate(
    findings: list[VulnFinding],
    gate: HITLGate,
    dry_run: bool,
) -> list[RemediationEntry]:
    entries: list[RemediationEntry] = []

    for f in findings:
        ts = datetime.now(timezone.utc).isoformat()
        print(f"\n[govern] {f.vuln_id} [{f.severity}]  {f.package} {f.installed_version}")

        if not f.fix_version:
            print("  No fix version — skipping")
            entries.append(
                RemediationEntry(
                    timestamp=ts,
                    vuln_id=f.vuln_id,
                    package=f.package,
                    installed_version=f.installed_version,
                    fix_version=None,
                    severity=f.severity,
                    action="skipped",
                    proposal_id=None,
                    ado_id=None,
                    approved_by=None,
                    detail="No fix version available",
                )
            )
            continue

        proposal = make_proposal(f)
        result = gate.evaluate(proposal)

        if isinstance(result, DeniedDecision):
            summary = result.to_human_summary()
            print(f"  DENIED — {summary['reason'][:80]}")
            entries.append(
                RemediationEntry(
                    timestamp=ts,
                    vuln_id=f.vuln_id,
                    package=f.package,
                    installed_version=f.installed_version,
                    fix_version=f.fix_version,
                    severity=f.severity,
                    action="denied",
                    proposal_id=str(proposal.decision_id),
                    ado_id=None,
                    approved_by=None,
                    detail=summary["reason"],
                )
            )
        else:
            ado = result
            print(f"  AUTHORIZED — ADO {ado.decision_id[:8]}…  dsal={ado.authorized_dsal}")
            detail = apply_patch(f, dry_run=dry_run)
            print(f"  {detail}")
            gate.register_executed(ado, _AGENT_ID)
            entries.append(
                RemediationEntry(
                    timestamp=ts,
                    vuln_id=f.vuln_id,
                    package=f.package,
                    installed_version=f.installed_version,
                    fix_version=f.fix_version,
                    severity=f.severity,
                    action="dry-run" if dry_run else "executed",
                    proposal_id=str(proposal.decision_id),
                    ado_id=str(ado.decision_id),
                    approved_by=getattr(ado, "authority", "auto"),
                    detail=detail,
                )
            )

    return entries


# ---------------------------------------------------------------------------
# 5. LangGraph orchestration (optional; falls back to direct loop if unavailable)
# ---------------------------------------------------------------------------


def build_graph(gate: HITLGate, dry_run: bool):
    from langgraph.graph import END, START, StateGraph
    from typing import TypedDict

    class State(TypedDict):
        findings: list[dict]
        entries: list[dict]

    def scan_node(state: State) -> dict:
        return {"findings": [asdict(f) for f in run_scan()]}

    def remediate_node(state: State) -> dict:
        findings = [VulnFinding(**d) for d in state["findings"]]
        return {"entries": [asdict(e) for e in remediate(findings, gate, dry_run)]}

    g = StateGraph(State)
    g.add_node("scan", scan_node)
    g.add_node("remediate", remediate_node)
    g.add_edge(START, "scan")
    g.add_edge("scan", "remediate")
    g.add_edge("remediate", END)
    return g.compile()


# ---------------------------------------------------------------------------
# 6. Audit writer
# ---------------------------------------------------------------------------


def write_audit(entries: list[RemediationEntry], path: Path, mode: str) -> None:
    executed = sum(1 for e in entries if e.action == "executed")
    denied = sum(1 for e in entries if e.action == "denied")
    skipped = sum(1 for e in entries if e.action in ("skipped", "dry-run"))

    audit = {
        "schema_version": "1",
        "run_at": datetime.now(timezone.utc).isoformat(),
        "agent_id": _AGENT_ID,
        "mode": mode,
        "summary": {
            "total": len(entries),
            "executed": executed,
            "denied": denied,
            "skipped": skipped,
        },
        "entries": [asdict(e) for e in entries],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(audit, indent=2, ensure_ascii=False))
    print(f"\n[audit] {path}  (executed={executed} denied={denied} skipped={skipped})")


# ---------------------------------------------------------------------------
# 7. Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    auto = os.getenv("SHANI_HITL_AUTO", "0") == "1"
    dry_run = os.getenv("SHANI_DRY_RUN", "0") == "1"
    use_lg = os.getenv("USE_LANGGRAPH", "0") == "1"
    audit_path = Path(os.getenv("AUDIT_OUTPUT", "audit.json"))

    mode_parts = []
    if auto:
        mode_parts.append("auto")
    if dry_run:
        mode_parts.append("dry-run")
    if use_lg:
        mode_parts.append("langgraph")
    mode = "+".join(mode_parts) if mode_parts else "manual"

    print("=" * 60)
    print("  Vulnerability Scan + Auto Remediation — Shani")
    print("=" * 60)
    print(f"  mode={mode}  audit={audit_path}")

    # Shani governance setup
    policy = DecisionPolicyProvider.from_yaml(_POLICY_PATH)
    authority = StaticAuthorityProvider(max_dsal=3)
    evaluator = ShaniEvaluator(authority_provider=authority, decision_policy=policy)

    if auto:
        # Auto-approve channel for CI / cron: immediately approves every HITL request.
        # The evaluator's own policy checks still run — human approval is necessary but
        # not sufficient. D-SAL 0/1 proposals bypass HITL entirely.
        _auto_ch: CallbackApprovalChannel

        def _auto_approve(req) -> None:  # type: ignore[no-untyped-def]
            _auto_ch.approve(req.request_id, "auto-ci", "CI/cron auto-approve")

        _auto_ch = CallbackApprovalChannel(on_new_request=_auto_approve)
        channel: CallbackApprovalChannel | CLIApprovalChannel = _auto_ch
    else:
        channel = CLIApprovalChannel()

    gate = HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=2,  # SecOps-Lead required for D-SAL >= 2
        timeout_minutes=15,
    )

    # Execute workflow
    if use_lg:
        try:
            graph = build_graph(gate, dry_run)
            final = graph.invoke({"findings": [], "entries": []})
            entries = [RemediationEntry(**d) for d in final["entries"]]
        except ImportError:
            print("  langgraph not installed — falling back to direct loop")
            entries = remediate(run_scan(), gate, dry_run)
    else:
        entries = remediate(run_scan(), gate, dry_run)

    write_audit(entries, audit_path, mode)
    print("\n  Done.")


if __name__ == "__main__":
    main()
