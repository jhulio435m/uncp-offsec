"""Bounded HTTP response-header assessment."""

from __future__ import annotations

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo
from .tools import run as run_tool

MODULE_NAME = "headers"
_CHECKS = {
    "strict-transport-security": ("HSTS", Severity.MEDIUM, "Enable HSTS after confirming HTTPS is available."),
    "content-security-policy": ("Content-Security-Policy", Severity.LOW, "Add a restrictive Content-Security-Policy."),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW, "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("X-Frame-Options", Severity.LOW, "Set X-Frame-Options or CSP frame-ancestors."),
    "referrer-policy": ("Referrer-Policy", Severity.LOW, "Set a privacy-preserving Referrer-Policy."),
}


def _parse(raw: str) -> dict[str, str]:
    return {key.strip().lower(): value.strip() for line in raw.splitlines() if ":" in line for key, value in [line.split(":", 1)]}


def _weak_csp(value: str) -> bool:
    """Return whether CSP lacks directives that restrict executable content."""
    directives = {item.strip().split(None, 1)[0].lower() for item in value.split(";") if item.strip()}
    return not directives.intersection({"default-src", "script-src", "script-src-elem"})


def run(hosts: list[HostInfo], *, timeout: int = 10, limit: int = 30) -> ModuleResult:
    """Fetch headers only; no path discovery or authentication attempts."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=0.0)
    candidates = [host for host in hosts if 200 <= host.status < 400][:limit]
    if not candidates:
        result.assessed = False
        result.findings.append(Finding(module=MODULE_NAME, severity=Severity.INFO, title="No reachable hosts for header review", detail="", recommendation=""))
        return result
    missing = {key: [] for key in _CHECKS}
    weak_csp: list[str] = []
    for host in candidates:
        tool = run_tool(["curl", "-ksSI", "--max-time", str(timeout), host.url], timeout=timeout + 5)
        if tool.ok:
            host.headers = _parse(tool.stdout)
            for key, affected in missing.items():
                if key not in host.headers:
                    affected.append(host.url)
            csp = host.headers.get("content-security-policy")
            if csp and _weak_csp(csp):
                weak_csp.append(f"{host.url}: {csp}")
    result.assessed = True
    result.findings.append(Finding(module=MODULE_NAME, severity=Severity.INFO, title=f"HTTP header review on {len(candidates)} host(s)", detail="Observed headers are preserved per asset.", recommendation=""))
    for key, affected in missing.items():
        if affected:
            label, severity, recommendation = _CHECKS[key]
            result.findings.append(Finding(module=MODULE_NAME, severity=severity, title=f"{label} missing on {len(affected)} host(s)", detail="\n".join(affected[:20]), recommendation=recommendation))
    if weak_csp:
        result.findings.append(Finding(
            module=MODULE_NAME,
            severity=Severity.LOW,
            title=f"Content-Security-Policy does not restrict scripts on {len(weak_csp)} host(s)",
            detail="\n".join(weak_csp[:20]),
            recommendation=(
                "Define default-src and a restrictive script-src, then add only the sources "
                "required by the application."
            ),
            confidence="HIGH",
            verification_status="OBSERVED",
        ))
    return result
