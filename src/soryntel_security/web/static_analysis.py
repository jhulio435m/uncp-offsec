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


# Lockfiles and resolved manifests that Trivy's filesystem scanner reads. A
# manifest without a lockfile has no resolved versions to correlate.
LOCKFILES: dict[str, str] = {
    "requirements.txt": "Python", "requirements.lock": "Python", "Pipfile.lock": "Python",
    "poetry.lock": "Python", "uv.lock": "Python",
    "package-lock.json": "Node.js", "yarn.lock": "Node.js", "pnpm-lock.yaml": "Node.js",
    "composer.lock": "PHP",
    "Gemfile.lock": "Ruby",
    "go.mod": "Go",
    "Cargo.lock": "Rust",
    "pom.xml": "Java", "gradle.lockfile": "Java",
    "packages.lock.json": ".NET",
}
# Manifest -> lockfiles that would make it resolvable.
UNLOCKED: dict[str, tuple[str, tuple[str, ...]]] = {
    "package.json": ("Node.js", ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")),
    "composer.json": ("PHP", ("composer.lock",)),
    "Gemfile": ("Ruby", ("Gemfile.lock",)),
    "Cargo.toml": ("Rust", ("Cargo.lock",)),
    "pyproject.toml": ("Python", ("poetry.lock", "uv.lock", "requirements.txt", "requirements.lock", "Pipfile.lock")),
}
SOURCE_LANGUAGES: dict[str, str] = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".php": "PHP", ".rb": "Ruby", ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin",
    ".cs": "C#", ".c": "C", ".cpp": "C++", ".swift": "Swift", ".scala": "Scala",
}
MAX_WALK_FILES = 20_000


def _walk(source: Path):
    """Yield files under source, skipping vendored and build directories."""
    seen = 0
    for root, dirs, files in os.walk(source):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_SOURCE_DIRS and not name.startswith("."))
        for name in sorted(files):
            seen += 1
            if seen > MAX_WALK_FILES:
                return
            yield Path(root) / name


def detect_manifests(source: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return ({ecosystem: lockfiles}, {ecosystem: manifests without a lockfile})."""
    locked: dict[str, list[str]] = {}
    unlocked: dict[str, list[str]] = {}
    by_dir: dict[Path, set[str]] = {}
    for path in _walk(source):
        by_dir.setdefault(path.parent, set()).add(path.name)
    for directory, names in sorted(by_dir.items()):
        for name in sorted(names):
            if name in LOCKFILES:
                locked.setdefault(LOCKFILES[name], []).append(str((directory / name).relative_to(source)))
        for name, (ecosystem, locks) in UNLOCKED.items():
            if name in names and not names.intersection(locks):
                unlocked.setdefault(ecosystem, []).append(str((directory / name).relative_to(source)))
    return locked, unlocked


def detect_languages(source: Path) -> dict[str, int]:
    """Count source files per language by extension."""
    counts: dict[str, int] = {}
    for path in _walk(source):
        language = SOURCE_LANGUAGES.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


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
    languages = detect_languages(source)
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
    if languages:
        result.findings.append(Finding(
            "sast", Severity.INFO, "Source languages found",
            "\n".join(f"{name}: {count} file(s)" for name, count in languages.items()),
            "", confidence="HIGH",
        ))
    not_python = [name for name in languages if name != "Python"]
    if not semgrep and bandit and not_python:
        # Bandit only understands Python: say so instead of implying the rest was reviewed.
        result.assessed = False
        result.findings.append(Finding(
            "sast", Severity.INFO, "Non-Python source was not analysed",
            "Bandit only analyses Python. Not analysed: " + ", ".join(not_python),
            "Install Semgrep to cover the remaining languages.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
    return result


def sca(source: Path) -> ModuleResult:
    """Run Trivy filesystem dependency scanning, falling back to pip-audit."""
    result = ModuleResult(name="sca")
    trivy = which("trivy")
    pip_audit = which("pip-audit")
    rows: list[dict] = []
    locked, unlocked = detect_manifests(source)
    if trivy:
        cache_dir = os.environ.get("TRIVY_CACHE_DIR", "/tmp/soryntel-security-trivy-cache")
        tool = run_tool([trivy, "fs", "--cache-dir", cache_dir, "--format", "json", "--scanners", "vuln", "--quiet", str(source)], timeout=600)
        try:
            payload = json.loads(tool.stdout or "{}")
            for target in payload.get("Results", []):
                for vuln in target.get("Vulnerabilities") or []:
                    rows.append({**vuln, "Target": target.get("Target", ""), "Type": target.get("Type", "")})
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
            f"Target: {row.get('Target', '')}"
            + (f"\nEcosystem: {row.get('Type')}" if row.get("Type") else "")
            + f"\nInstalled: {row.get('InstalledVersion', '')}\nFixed: {row.get('FixedVersion', '')}",
            "Update to a vendor-supported fixed version after compatibility testing.", confidence="HIGH",
            verification_status="VERSION_CORRELATED", cve_ids=[cve] if cve.startswith("CVE-") else [],
            owasp_categories=["A03:2025", "A08:2025"],
        ))
    if result.assessed and not result.findings:
        result.findings.append(Finding("sca", Severity.PASS, "No known dependency vulnerabilities", "No advisory matched the resolved manifest; unknown and unpublished flaws remain possible.", ""))
    if locked:
        result.findings.append(Finding(
            "sca", Severity.INFO, "Dependency manifests found",
            "\n".join(f"{ecosystem}: {', '.join(paths[:8])}" for ecosystem, paths in sorted(locked.items())),
            "", confidence="HIGH",
        ))
    if unlocked:
        result.findings.append(Finding(
            "sca", Severity.LOW, "Manifests without a lockfile",
            "\n".join(f"{ecosystem}: {', '.join(paths[:8])}" for ecosystem, paths in sorted(unlocked.items()))
            + "\nWithout resolved versions these dependencies cannot be correlated with advisories.",
            "Commit the lockfile so dependency versions can be audited.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
    not_python = sorted(ecosystem for ecosystem in locked if ecosystem != "Python")
    if not trivy and pip_audit and not_python:
        # pip-audit only reads Python requirements: the other ecosystems were not checked.
        result.assessed = False
        result.findings.append(Finding(
            "sca", Severity.INFO, "Non-Python dependencies were not analysed",
            "pip-audit only analyses Python requirements. Not analysed: " + ", ".join(not_python),
            "Install Trivy to cover the remaining ecosystems.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
    return result
