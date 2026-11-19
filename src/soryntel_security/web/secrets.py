"""Credentials committed to an authorized source tree.

Trivy's secret scanner is used when available; otherwise a small built-in set
of high-confidence patterns. Either way the report states where a credential
is and what kind it is, never its value.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from mailsec.models import Finding, ModuleResult, Severity

from .static_analysis import _severity, _walk
from .tools import run as run_tool
from .tools import which

MODULE_NAME = "secrets"
MAX_FILE_BYTES = 1_000_000

# (rule id, title, severity, pattern). Only formats specific enough to trust.
PATTERNS: tuple[tuple[str, str, Severity, re.Pattern[str]], ...] = (
    ("aws-access-key-id", "AWS Access Key ID", Severity.CRITICAL, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", "Private key", Severity.HIGH, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("github-token", "GitHub token", Severity.CRITICAL, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", "Slack token", Severity.HIGH, re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", "Slack webhook", Severity.MEDIUM, re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("google-api-key", "Google API key", Severity.HIGH, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-live-key", "Stripe live secret key", Severity.CRITICAL, re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
)
# Files that usually hold credentials; their presence in a repository is worth a look.
SENSITIVE_NAMES = re.compile(r"^(\.env(\..+)?|id_(rsa|dsa|ecdsa|ed25519)|.+\.(pem|p12|pfx|key|keystore|jks)|credentials\.json)$")
SAFE_ENV_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist"}

ROTATE = "Revoke and rotate the credential, remove it from the repository history, and load it from a secret manager or environment variable."


def builtin_scan(source: Path) -> list[dict]:
    """Return {rule, title, severity, file, line} for each pattern match; never the matched value."""
    hits = []
    for path in _walk(source):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for rule, title, severity, pattern in PATTERNS:
                if pattern.search(line):
                    hits.append({"rule": rule, "title": title, "severity": severity,
                                 "file": str(path.relative_to(source)), "line": number})
    return hits


def sensitive_files(source: Path) -> list[str]:
    """Return credential-style files present in the tree, by name only."""
    return sorted(
        str(path.relative_to(source)) for path in _walk(source)
        if SENSITIVE_NAMES.match(path.name) and path.name not in SAFE_ENV_NAMES
    )


def run(source: Path) -> ModuleResult:
    """Look for committed credentials in source."""
    result = ModuleResult(name=MODULE_NAME)
    trivy = which("trivy")
    hits: list[dict] = []
    if trivy:
        cache_dir = os.environ.get("TRIVY_CACHE_DIR", "/tmp/soryntel-security-trivy-cache")
        tool = run_tool([trivy, "fs", "--cache-dir", cache_dir, "--format", "json", "--scanners", "secret", "--quiet", str(source)], timeout=600)
        try:
            payload = json.loads(tool.stdout or "{}")
        except json.JSONDecodeError:
            payload = None
        if payload is None or (not tool.ok and not payload.get("Results")):
            result.assessed = False
            result.findings.append(Finding(
                MODULE_NAME, Severity.INFO, "Secret scan incomplete", (tool.stderr or tool.stdout)[:600],
                "Rerun the secret scan; until then committed credentials are not ruled out.",
                confidence="HIGH", verification_status="TOOL_INCOMPLETE",
            ))
            return result
        for target in payload.get("Results", []):
            for secret in target.get("Secrets") or []:
                # Trivy masks the value in "Match"; it is deliberately not copied into the report.
                hits.append({
                    "rule": str(secret.get("RuleID") or "secret"), "title": str(secret.get("Title") or "Secret"),
                    "severity": _severity(str(secret.get("Severity") or "high")),
                    "file": str(target.get("Target", "")), "line": secret.get("StartLine", ""),
                })
    else:
        hits = builtin_scan(source)
        result.findings.append(Finding(
            MODULE_NAME, Severity.INFO, "Built-in secret patterns used",
            f"Trivy is not installed, so only {len(PATTERNS)} high-confidence credential formats were checked.",
            "Install Trivy for wider credential coverage.", confidence="HIGH",
        ))

    groups: dict[tuple[str, str], list[dict]] = {}
    for hit in hits:
        groups.setdefault((hit["rule"], hit["title"]), []).append(hit)
    for (rule, title), instances in sorted(groups.items()):
        severity = max((item["severity"] for item in instances), key=lambda item: list(Severity).index(item))
        result.findings.append(Finding(
            MODULE_NAME, severity, f"{title} committed to the source tree",
            f"Rule: {rule}\nOccurrences: {len(instances)}\n"
            + "\n".join(f"File: {item['file']}:{item['line']}" for item in instances[:20])
            + "\nThe value is not included in this report.",
            ROTATE, confidence="MEDIUM", verification_status="STATIC_SIGNAL",
            owasp_categories=["A04:2025", "A07:2025"], occurrence_count=len(instances),
        ))

    files = sensitive_files(source)
    if files:
        result.findings.append(Finding(
            MODULE_NAME, Severity.LOW, "Credential-style files in the source tree",
            "\n".join(files[:30]),
            "Confirm these files hold no live credentials and keep them out of version control.",
            confidence="LOW", verification_status="POTENTIAL", occurrence_count=len(files),
        ))
    if not hits and not files:
        result.findings.append(Finding(
            MODULE_NAME, Severity.PASS, "No committed credentials found",
            "No known credential format matched the current files. Git history was not scanned.", "",
        ))
    elif hits:
        result.findings.append(Finding(
            MODULE_NAME, Severity.INFO, "Scope of the secret scan",
            "Only the current files were scanned. A credential removed in a later commit is still in the Git history.",
            "", confidence="HIGH",
        ))
    return result
