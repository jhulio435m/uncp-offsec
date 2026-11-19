"""Strictly bounded SQLi detection over approved GET candidates."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from mailsec.models import Finding, ModuleResult, Severity

from .tools import run as run_tool
from .tools import which


def is_positive_detection(output: str) -> bool:
    """Accept explicit SQLMap confirmations without matching negative prose."""
    normalized = output.lower()
    negative = (
        "does not seem to be injectable",
        "not injectable",
        "might not be injectable",
        "no parameter(s) found",
    )
    if any(phrase in normalized for phrase in negative):
        return False
    return any(
        phrase in normalized
        for phrase in (
            "is vulnerable",
            "appears to be injectable",
            "identified the following injection point",
        )
    )


def candidates(urls: list[str], excluded_paths: tuple[str, ...], limit: int) -> list[str]:
    """Keep only parameterized GET URLs outside explicitly excluded paths."""
    approved = []
    for url in sorted(set(urls)):
        parsed = urlparse(url)
        if not parsed.query or any(parsed.path.startswith(path) for path in excluded_paths):
            continue
        approved.append(url)
    return approved[:limit]


def request_metadata(path: Path) -> tuple[str, str]:
    """Return Host and request path from a raw HTTP request accepted by SQLMap -r."""
    text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
    lines = text.splitlines()
    request_path = ""
    if lines:
        match = re.match(r"^[A-Z]+\s+(\S+)\s+HTTP/", lines[0].strip())
        request_path = match.group(1) if match else ""
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip().split(":", 1)[0].lower().rstrip(".")
            break
    return host, request_path


def run(
    urls: list[str],
    *,
    excluded_paths: tuple[str, ...],
    limit: int,
    request_files: tuple[Path, ...] = (),
    headers: dict[str, str] | None = None,
) -> ModuleResult:
    """Detect SQLi only; intentionally omits enumeration, file access and shell options."""
    result = ModuleResult(name="sqli", score_contribution=0.0, max_score=0.0)
    targets = candidates(urls, excluded_paths, limit)
    path = which("sqlmap")
    approved_requests = []
    for request_file in request_files:
        _host, request_path = request_metadata(request_file)
        if any(request_path.startswith(excluded) for excluded in excluded_paths):
            continue
        approved_requests.append(request_file)
    if not targets and not approved_requests:
        result.assessed = False
        result.findings.append(Finding(
            module="sqli", severity=Severity.INFO, title="No SQLi candidates discovered",
            detail="Katana found no parameterized GET URLs eligible for SQLMap.",
            recommendation="Supply an authorized raw request when important parameters use POST or JSON.",
            confidence="HIGH", verification_status="NO_CANDIDATES",
        ))
        return result
    if not path:
        result.assessed = False
        result.findings.append(Finding(
            module="sqli", severity=Severity.INFO, title="SQLMap unavailable",
            detail="Candidate URLs exist, but sqlmap was not found on PATH.",
            recommendation="Install SQLMap or use the complete container image.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
        return result
    result.assessed = True
    for url in targets:
        cmd = [path, "-u", url, "--batch", "--level=1", "--risk=1", "--threads=1", "--timeout=10", "--retries=0", "--smart", "--flush-session", "--disable-coloring"]
        if headers:
            cmd.extend(["--headers", "\n".join(f"{name}: {value}" for name, value in headers.items())])
        tool = run_tool(cmd, timeout=90)
        output = f"{tool.stdout}\n{tool.stderr}".lower()
        if is_positive_detection(output):
            result.findings.append(Finding(module="sqli", severity=Severity.HIGH, title="SQL injection validated by SQLMap", detail=f"Candidate: {url}\nDetection-only run; no database enumeration or data extraction was requested.", recommendation="Use parameterized queries and least-privilege database credentials.", confidence="HIGH", verification_status="VALIDATED_NON_DESTRUCTIVE", owasp_categories=["A05:2025"]))
    for request_file in approved_requests[:limit]:
        tool = run_tool([path, "-r", str(request_file), "--batch", "--level=3", "--risk=2", "--threads=1", "--timeout=10", "--retries=0", "--flush-session", "--disable-coloring"], timeout=180)
        output = f"{tool.stdout}\n{tool.stderr}".lower()
        if is_positive_detection(output):
            result.findings.append(Finding(module="sqli", severity=Severity.HIGH, title="SQL injection validated by SQLMap", detail=f"Raw request: {request_file.name}\nDetection-only validation; no database enumeration or data extraction was requested.", recommendation="Use parameterized queries and least-privilege database credentials.", confidence="HIGH", verification_status="VALIDATED_NON_DESTRUCTIVE", owasp_categories=["A05:2025"]))
    if not result.findings:
        count = len(targets) + len(approved_requests[:limit])
        result.findings.append(Finding(module="sqli", severity=Severity.INFO, title=f"No SQLi signal in {count} bounded candidate(s)", detail="This is not proof that the application is free of SQL injection.", recommendation=""))
    return result
