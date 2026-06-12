"""
examples/vuln-remediation/shani_vuln_judge.py

Read trivy / grype / osv-scanner JSON output and evaluate each finding
through Shani governance.  In CI mode (SHANI_HITL_AUTO=1) all HITL gates
auto-approve; the policy engine still applies.  Produces a structured audit
JSON with an authorized / denied / skipped verdict per finding.

Usage:
    python shani_vuln_judge.py \
        --trivy  trivy-repo.json [trivy-dist.json ...] \
        --grype  grype-repo.json [grype-dist.json ...] \
        --osv    osv-results.json \
        --output shani-audit.json \
        [--policy ../../policy/decision_policy.yaml] \
        [--dry-run] \
        [--fail-on-denied]

Environment:
    SHANI_HITL_AUTO=1  (default 1 — auto-approve HITL gates for CI)
    SHANI_DRY_RUN=1    evaluate only, skip register_executed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT))

# pyyaml shim — pyyaml is an optional dep; auto-install when missing
try:
    import yaml  # noqa: F401
except ImportError:
    import subprocess as _sp
    _sp.check_call([sys.executable, "-m", "pip", "install", "--quiet", "pyyaml"])

# pydantic shim — mirrors pattern from scenario.py
try:
    import pydantic  # noqa: F401
except ImportError:
    import types as _t
    import importlib.util as _iu
    import pathlib as _pl

    _s = _iu.spec_from_file_location("_compat", str(_ROOT / "shani/_compat.py"))
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
from shani.hitl.channel.channels import CallbackApprovalChannel, CLIApprovalChannel
from shani.schemas.decision import DecisionProposal, EvidenceItem

_POLICY_PATH = Path(__file__).parent / "policy.yaml"
_AGENT_ID = "vuln-scan-judge/v1"

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    vuln_id: str
    package: str
    installed_version: str
    fix_version: str | None
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    source: str  # trivy / grype / osv-scanner


@dataclass
class JudgmentEntry:
    timestamp: str
    vuln_id: str
    package: str
    installed_version: str
    fix_version: str | None
    severity: str
    source: str
    verdict: str  # authorized / denied / skipped
    proposal_id: str | None
    ado_id: str | None
    reason: str


# ---------------------------------------------------------------------------
# Scanner JSON parsers
# ---------------------------------------------------------------------------


def _severity_from_float(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_severity(raw: str | None) -> str:
    if not raw:
        return "MEDIUM"
    upper = raw.strip().upper()
    if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return upper
    # Try numeric CVSS score
    try:
        return _severity_from_float(float(upper))
    except ValueError:
        return "MEDIUM"


def parse_trivy(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    vuln_id=v.get("VulnerabilityID", "unknown"),
                    package=v.get("PkgName", "unknown"),
                    installed_version=v.get("InstalledVersion", "unknown"),
                    fix_version=v.get("FixedVersion") or None,
                    severity=_parse_severity(v.get("Severity")),
                    description=(v.get("Description") or v.get("Title") or "")[:300],
                    source="trivy",
                )
            )
    return findings


def parse_grype(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix_versions = vuln.get("fix", {}).get("versions", [])
        findings.append(
            Finding(
                vuln_id=vuln.get("id", "unknown"),
                package=artifact.get("name", "unknown"),
                installed_version=artifact.get("version", "unknown"),
                fix_version=fix_versions[0] if fix_versions else None,
                severity=_parse_severity(vuln.get("severity")),
                description=(vuln.get("description") or "")[:300],
                source="grype",
            )
        )
    return findings


def parse_osv(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                # Extract earliest fix version from affected ranges
                fix_version = None
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fix_version = event["fixed"]
                                break
                        if fix_version:
                            break
                    if fix_version:
                        break

                # Extract numeric CVSS score when present
                severity = "MEDIUM"
                for sev in vuln.get("severity", []):
                    try:
                        severity = _severity_from_float(float(sev.get("score", "")))
                        break
                    except (ValueError, TypeError):
                        pass

                findings.append(
                    Finding(
                        vuln_id=vuln.get("id", "unknown"),
                        package=pkg_info.get("name", "unknown"),
                        installed_version=pkg_info.get("version", "unknown"),
                        fix_version=fix_version,
                        severity=severity,
                        description=(
                            vuln.get("summary") or vuln.get("details") or ""
                        )[:300],
                        source="osv-scanner",
                    )
                )
    return findings

def parse_sarif(path: Path) -> list[Finding]:
    """Parse SARIF 2.1.0 output from VVAH or any SARIF-compliant scanner."""
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules = {
            r["id"]: r 
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            
            # location
            locations = result.get("locations", [])
            file_path = "unknown"
            if locations:
                pl = locations[0].get("physicalLocation", {})
                file_path = pl.get("artifactLocation", {}).get("uri", "unknown")
            
            # severity from SARIF level
            level = result.get("level", "warning")
            severity_map = {
                "error": "HIGH",
                "warning": "MEDIUM", 
                "note": "LOW",
                "none": "LOW",
            }
            
            # prefer CVSS-based severity if available in properties
            props = result.get("properties", {})
            cvss_score = props.get("cvss_score")
            severity = _severity_from_float(cvss_score) if cvss_score else severity_map.get(level, "MEDIUM")
            
            # skip FALSE_POSITIVE verdicts from VVAH
            if props.get("verdict") == "FALSE_POSITIVE":
                continue
            
            message = result.get("message", {}).get("text", "")
            
            findings.append(Finding(
                vuln_id=rule_id,
                package=file_path,
                installed_version="n/a",
                fix_version=props.get("recommendation"),
                severity=severity,
                description=(
                    rule.get("fullDescription", {}).get("text", "") or message
                )[:300],
                source="sarif",
            ))
    
    return findings

def load_findings(
    trivy: list[Path], grype: list[Path], osv: list[Path], sarif: list[Path] = []
) -> list[Finding]:
    all_findings: list[Finding] = []
    for p in trivy:
        all_findings.extend(parse_trivy(p))
    for p in grype:
        all_findings.extend(parse_grype(p))
    for p in osv:
        all_findings.extend(parse_osv(p))
    for p in sarif:
        all_findings.extend(parse_sarif(p))

    # Deduplicate by (package, vuln_id); keep highest-severity copy
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    seen: dict[tuple[str, str], Finding] = {}
    for f in all_findings:
        key = (f.package, f.vuln_id)
        if key not in seen or _order.get(f.severity, 4) < _order.get(
            seen[key].severity, 4
        ):
            seen[key] = f

    return sorted(seen.values(), key=lambda f: _order.get(f.severity, 4))


# ---------------------------------------------------------------------------
# Shani evaluation
# ---------------------------------------------------------------------------

_SEVERITY_BLAST: dict[str, BlastRadius] = {
    "CRITICAL": BlastRadius.SIGNIFICANT,
    "HIGH": BlastRadius.LIMITED,
    "MEDIUM": BlastRadius.ISOLATED,
    "LOW": BlastRadius.ISOLATED,
}


def _make_proposal(f: Finding) -> DecisionProposal:
    desc = f"Upgrade {f.package} {f.installed_version}"
    if f.fix_version:
        desc += f" → {f.fix_version}"
    desc += f" to fix {f.vuln_id} [{f.severity}]"
    return DecisionProposal(
        decision_type=DecisionType.REMEDIATION,
        proposed_by=_AGENT_ID,
        description=desc,
        target=f"package:{f.package}",
        blast_radius=_SEVERITY_BLAST[f.severity],
        reversibility=True,
        evidence=[
            EvidenceItem(
                source=f.source,
                content=f"{f.vuln_id}: {f.description}",
                confidence=0.9,
            )
        ],
        confidence=0.9,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=60),
    )


def judge(
    findings: list[Finding], gate: HITLGate, dry_run: bool
) -> list[JudgmentEntry]:
    entries: list[JudgmentEntry] = []
    for f in findings:
        ts = datetime.now(timezone.utc).isoformat()
        print(
            f"[judge] {f.vuln_id} [{f.severity}]  "
            f"{f.package} {f.installed_version}  ({f.source})"
        )

        if not f.fix_version:
            print("  → SKIPPED (no fix version)")
            entries.append(
                JudgmentEntry(
                    timestamp=ts,
                    vuln_id=f.vuln_id,
                    package=f.package,
                    installed_version=f.installed_version,
                    fix_version=None,
                    severity=f.severity,
                    source=f.source,
                    verdict="skipped",
                    proposal_id=None,
                    ado_id=None,
                    reason="No fix version available",
                )
            )
            continue

        proposal = _make_proposal(f)
        result = gate.evaluate(proposal)

        if isinstance(result, DeniedDecision):
            summary = result.to_human_summary()
            reason = summary.get("reason", "denied by policy")[:120]
            print(f"  → DENIED  {reason}")
            entries.append(
                JudgmentEntry(
                    timestamp=ts,
                    vuln_id=f.vuln_id,
                    package=f.package,
                    installed_version=f.installed_version,
                    fix_version=f.fix_version,
                    severity=f.severity,
                    source=f.source,
                    verdict="denied",
                    proposal_id=str(proposal.decision_id),
                    ado_id=None,
                    reason=reason,
                )
            )
        else:
            ado = result
            print(
                f"  → AUTHORIZED  ADO={str(ado.decision_id)[:8]}…"
                f"  dsal={ado.authorized_dsal}"
            )
            if not dry_run:
                gate.register_executed(ado, _AGENT_ID)
            entries.append(
                JudgmentEntry(
                    timestamp=ts,
                    vuln_id=f.vuln_id,
                    package=f.package,
                    installed_version=f.installed_version,
                    fix_version=f.fix_version,
                    severity=f.severity,
                    source=f.source,
                    verdict="authorized",
                    proposal_id=str(proposal.decision_id),
                    ado_id=str(ado.decision_id),
                    reason=f"dsal={ado.authorized_dsal}",
                )
            )

    return entries


# ---------------------------------------------------------------------------
# Audit writer
# ---------------------------------------------------------------------------


def write_audit(
    entries: list[JudgmentEntry], output: Path, mode: str
) -> int:
    counts = {
        v: sum(1 for e in entries if e.verdict == v)
        for v in ("authorized", "denied", "skipped")
    }
    audit = {
        "schema_version": "1",
        "run_at": datetime.now(timezone.utc).isoformat(),
        "agent_id": _AGENT_ID,
        "mode": mode,
        "summary": {"total": len(entries), **counts},
        "entries": [asdict(e) for e in entries],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2, ensure_ascii=False))
    print(
        f"\n[audit] {output}  "
        f"total={len(entries)}  authorized={counts['authorized']}  "
        f"denied={counts['denied']}  skipped={counts['skipped']}"
    )
    return counts["denied"]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate vulnerability scan results through Shani governance"
    )
    parser.add_argument("--trivy", nargs="*", default=[], metavar="FILE")
    parser.add_argument("--grype", nargs="*", default=[], metavar="FILE")
    parser.add_argument("--osv", nargs="*", default=[], metavar="FILE")
    parser.add_argument("--sarif", nargs="*", default=[], metavar="FILE")
    parser.add_argument(
        "--policy", default=str(_POLICY_PATH), metavar="FILE"
    )
    parser.add_argument(
        "--output", default="shani-audit.json", metavar="FILE"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate policy but skip register_executed",
    )
    parser.add_argument(
        "--fail-on-denied",
        action="store_true",
        help="Exit 1 if any finding is denied by policy",
    )
    args = parser.parse_args()

    auto = os.getenv("SHANI_HITL_AUTO", "1") == "1"
    dry_run = args.dry_run or os.getenv("SHANI_DRY_RUN", "0") == "1"
    mode = "auto" + ("+dry-run" if dry_run else "")

    print("=" * 60)
    print("  Vulnerability Scan Results → Shani Governance Judgment")
    print("=" * 60)
    print(f"  mode={mode}  policy={args.policy}")

    findings = load_findings(
        trivy=[Path(p) for p in args.trivy],
        grype=[Path(p) for p in args.grype],
        osv=[Path(p) for p in args.osv],
        sarif=[Path(p) for p in args.sarif],
    )
    print(f"\n[load] {len(findings)} unique finding(s) after deduplication")

    if not findings:
        print("  Nothing to evaluate.")
        write_audit([], Path(args.output), mode)
        return

    policy = DecisionPolicyProvider.from_yaml(Path(args.policy))
    authority = StaticAuthorityProvider(max_dsal=3)
    evaluator = ShaniEvaluator(
        authority_provider=authority, decision_policy=policy
    )

    if auto:
        _auto_ch: CallbackApprovalChannel

        def _auto_approve(req) -> None:  # type: ignore[no-untyped-def]
            _auto_ch.approve(req.request_id, "auto-ci", "CI auto-approve")

        _auto_ch = CallbackApprovalChannel(on_new_request=_auto_approve)
        channel = _auto_ch
    else:
        channel = CLIApprovalChannel()

    gate = HITLGate(
        evaluator=evaluator,
        channel=channel,
        approval_required_at_dsal=2,
        timeout_minutes=15,
    )

    entries = judge(findings, gate, dry_run)
    denied_count = write_audit(entries, Path(args.output), mode)

    if args.fail_on_denied and denied_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
