"""Subdomain discovery via subfinder (ProjectDiscovery)."""

from __future__ import annotations

from mailsec.models import Finding, ModuleResult, Severity

from .tools import run as run_tool
from .tools import which

MODULE_NAME = "subdomains"
MAX_SCORE = 10.0

# Subdomain labels that typically indicate sensitive or admin surfaces.
_RISKY_PATTERNS = (
    "admin",
    "vpn",
    "dev",
    "staging",
    "test",
    "qa-",
    "git",
    "jenkins",
    "jira",
    "webmail",
    "owa",
    "mailout",
    "phpmyadmin",
    "pma",
    "panel",
    "cpanel",
    "whm",
    "api",
    "ws",
    "fts",
    "ftp",
    "nas",
    "share",
    "remote",
    "backup",
    "bkp",
    "dvr",
    "cctv",
    "cam",
    "radius",
    "fw",
    "firewall",
    "gateway",
    "rds",
    "bastion",
    "cicd",
    "runner",
    "loki",
    "grafana",
    "kibana",
    "es-",
    "redis",
    "db-",
    "mysql",
    "postgres",
)


def _classify(sub: str) -> str | None:
    """Return the matched risky keyword if the hostname smells sensitive."""
    lowered = sub.split(".")[0].lower()
    for pattern in _RISKY_PATTERNS:
        if pattern in lowered:
            return pattern
    return None


def parse_output(raw: str) -> list[str]:
    """Parse subfinder -silent stdout into a deduped, sorted hostname list."""
    seen: set[str] = set()
    for line in raw.splitlines():
        host = line.strip().lower()
        if host and host not in seen:
            seen.add(host)
    return sorted(seen)


def run(
    domain: str,
    *,
    timeout: float = 180.0,
    extra_sources: bool = True,
    resolvers: str | None = None,
) -> tuple[ModuleResult, list[str]]:
    """Discover subdomains with subfinder and flag sensitive assets."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    path = which("subfinder")
    if not path:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="subfinder not available",
                detail="Subdomain discovery skipped: subfinder binary not found on PATH.",
                recommendation="Install subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            )
        )
        return result, []

    cmd = [path, "-d", domain, "-silent"]
    if resolvers:
        cmd.extend(["-r", resolvers])
    if extra_sources:
        cmd.append("-all")
    tool = run_tool(cmd, timeout=timeout)
    if not tool.ok:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Subdomain discovery failed",
                detail=f"subfinder exited with rc={tool.returncode}.\n{tool.stderr.strip()[:400]}",
                recommendation="Re-run with network access to OSINT sources.",
            )
        )
        return result, []

    hosts = parse_output(tool.stdout)
    result.assessed = True
    if not hosts:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No subdomains found via OSINT",
                detail="subfinder returned no subdomains from its passive sources.",
                recommendation="Consider subdomain brute-force (ffuf -w wordlists/subdomains) as an authorized active supplement.",
            )
        )
        return result, hosts

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title=f"Discovered {len(hosts)} subdomains",
            detail="\n".join(hosts),
            recommendation="",
        )
    )

    risky = {h: k for h in hosts if (k := _classify(h))}
    if risky:
        detail = "\n".join(f"{h}  ({kw})" for h, kw in sorted(risky.items()))
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title=f"{len(risky)} potentially sensitive subdomains",
                detail=detail,
                recommendation="Validate whether each is still needed, restrict access controls, and remove abandoned assets.",
            )
        )

    return result, hosts
