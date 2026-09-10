"""Optional local SAST and SCA adapters for an authorized source tree."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mailsec.models import Finding, ModuleResult, Severity

from .tools import run as run_tool
from .tools import which

EXCLUDED_SOURCE_DIRS = (
    ".git", ".venv", "venv", ".tox", "node_modules", "vendor", "dist", "build", "reports", "test", "tests",
)


def _severity(value: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "error": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(value.lower(), Severity.INFO)


def sast(source: Path) -> ModuleResult:
    """Run Semgrep when available, falling back to Bandit for Python projects."""
    result = ModuleResult(name="sast")
    semgrep = which("semgrep")
    bandit = which("bandit")
    if semgrep:
        cmd = [semgrep, "scan", "--config", "p/default", "--json", "--metrics=off"]
        for excluded in EXCLUDED_SOURCE_DIRS:
            cmd.extend(["--exclude", excluded])
        tool = run_tool([*cmd, str(source)], timeout=600)
        try:
            rows = json.loads(tool.stdout or "{}").get("results", [])
        except json.JSONDecodeError:
            rows = []
        result.assessed = tool.ok or bool(rows)
        if not result.assessed:
            result.findings.append(Finding("sast", Severity.INFO, "Semgrep scan incomplete", (tool.stderr or tool.stdout)[:1000], "Verify registry access or provide a locally cached Semgrep ruleset."))
            return result
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(str(row.get("check_id") or "unknown"), []).append(row)
        for rule_id, instances in list(groups.items())[:500]:
            row = instances[0]
            extra = row.get("extra") or {}
            metadata = extra.get("metadata") or {}
            cwe = metadata.get("cwe") or []
            if isinstance(cwe, str):
                cwe = [cwe]
            result.findings.append(Finding(
                "sast", _severity(str(extra.get("severity") or "warning")),
                str(extra.get("message") or row.get("check_id") or "Semgrep finding"),
                f"Rule: {rule_id}\nOccurrences: {len(instances)}\n" + "\n".join(f"File: {item.get('path', '')}:{(item.get('start') or {}).get('line', '')}" for item in instances[:20]),
                "Review the data flow and remediate the unsafe code pattern.",
                rfc_ref=", ".join(str(item) for item in cwe[:3]), confidence="MEDIUM",
                verification_status="STATIC_SIGNAL", owasp_categories=["A05:2025", "A08:2025", "A10:2025"],
                occurrence_count=len(instances),
            ))
    elif bandit:
        excludes = ",".join(str(source / name) for name in EXCLUDED_SOURCE_DIRS)
        tool = run_tool([bandit, "-r", str(source), "-x", excludes, "-f", "json", "-q"], timeout=300)
        try:
            rows = json.loads(tool.stdout or "{}").get("results", [])
        except json.JSONDecodeError:
            rows = []
        result.assessed = tool.returncode in (0, 1) or bool(rows)
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(str(row.get("test_id") or "unknown"), []).append(row)
        for rule_id, instances in list(groups.items())[:500]:
            row = instances[0]
            result.findings.append(Finding(
                "sast", _severity(str(row.get("issue_severity") or "medium")),
                str(row.get("issue_text") or row.get("test_id") or "Bandit finding"),
                f"Rule: {rule_id}\nOccurrences: {len(instances)}\n" + "\n".join(f"File: {item.get('filename', '')}:{item.get('line_number', '')}" for item in instances[:20]),
                "Review and remediate the unsafe code pattern.", confidence=str(row.get("issue_confidence") or "MEDIUM"),
                verification_status="STATIC_SIGNAL", owasp_categories=["A05:2025", "A08:2025", "A10:2025"],
                occurrence_count=len(instances),
            ))
    else:
        result.assessed = False
        result.findings.append(Finding("sast", Severity.INFO, "SAST tool unavailable", "Install Semgrep or Bandit.", ""))
        return result
    if result.assessed and not result.findings:
        result.findings.append(Finding("sast", Severity.PASS, "No SAST findings", "No configured static rule matched; this is not proof of secure design.", ""))
    return result


def sca(source: Path) -> ModuleResult:
    """Run Trivy filesystem dependency scanning, falling back to pip-audit."""
    result = ModuleResult(name="sca")
    trivy = which("trivy")
    pip_audit = which("pip-audit")
    rows: list[dict] = []
    if trivy:
        cache_dir = os.environ.get("TRIVY_CACHE_DIR", "/tmp/uncp-trivy-cache")
        tool = run_tool([trivy, "fs", "--cache-dir", cache_dir, "--format", "json", "--scanners", "vuln", "--quiet", str(source)], timeout=600)
        try:
            payload = json.loads(tool.stdout or "{}")
            for target in payload.get("Results", []):
                for vuln in target.get("Vulnerabilities") or []:
                    rows.append({**vuln, "Target": target.get("Target", "")})
        except json.JSONDecodeError:
            pass
        result.assessed = tool.ok or bool(rows)
        if not result.assessed:
            result.findings.append(Finding("sca", Severity.INFO, "Trivy scan incomplete", (tool.stderr or tool.stdout)[:1000], "Verify vulnerability database access or configure a persistent Trivy cache."))
            return result
    elif pip_audit:
        candidates = [source / name for name in ("requirements.txt", "requirements.lock") if (source / name).is_file()]
        if not candidates:
            result.assessed = False
            result.findings.append(Finding("sca", Severity.INFO, "No supported dependency manifest", "Trivy is unavailable and no Python requirements file was found.", ""))
            return result
        tool = run_tool([pip_audit, "-r", str(candidates[0]), "-f", "json", "--disable-pip"], timeout=600)
        try:
            parsed = json.loads(tool.stdout or "[]")
            dependencies = parsed.get("dependencies", []) if isinstance(parsed, dict) else parsed
            for dep in dependencies:
                for vuln in dep.get("vulns") or []:
                    rows.append({"VulnerabilityID": vuln.get("id"), "PkgName": dep.get("name"), "InstalledVersion": dep.get("version"), "FixedVersion": ", ".join(vuln.get("fix_versions") or []), "Severity": "HIGH"})
        except json.JSONDecodeError:
            pass
        result.assessed = tool.returncode in (0, 1) or bool(rows)
    else:
        result.assessed = False
        result.findings.append(Finding("sca", Severity.INFO, "SCA tool unavailable", "Install Trivy or pip-audit.", ""))
        return result
    for row in rows[:500]:
        cve = str(row.get("VulnerabilityID") or "")
        result.findings.append(Finding(
            "sca", _severity(str(row.get("Severity") or "high")),
            f"{cve or 'Dependency advisory'} in {row.get('PkgName', '')}",
            f"Target: {row.get('Target', '')}\nInstalled: {row.get('InstalledVersion', '')}\nFixed: {row.get('FixedVersion', '')}",
            "Update to a vendor-supported fixed version after compatibility testing.", confidence="HIGH",
            verification_status="VERSION_CORRELATED", cve_ids=[cve] if cve.startswith("CVE-") else [],
            owasp_categories=["A03:2025", "A08:2025"],
        ))
    if result.assessed and not result.findings:
        result.findings.append(Finding("sca", Severity.PASS, "No known dependency vulnerabilities", "No advisory matched the resolved manifest; unknown and unpublished flaws remain possible.", ""))
    return result
