"""Technology fingerprinting via whatweb."""

from __future__ import annotations

import json
from pathlib import Path

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo
from .tools import run as run_tool
from .tools import temporary_output, which

MODULE_NAME = "technology"
MAX_SCORE = 8.0

# Platforms that demand extra hardening / patch discipline.
_RISKY_TECH = {
    "wordpress": (Severity.MEDIUM, "WordPress requires strict plugin/theme and update hygiene."),
    "phpmyadmin": (Severity.HIGH, "phpMyAdmin exposes DB administration; restrict by IP/VPN."),
    "drupal": (Severity.MEDIUM, "Drupal has a record of critical CVEs; keep modules updated."),
    "joomla": (Severity.MEDIUM, "Joomla is a frequent brute-force target."),
    "moodle": (Severity.LOW, "Moodle installs need version tracking for CVEs."),
    "tomcat": (Severity.MEDIUM, "Apache Tomcat manager/backend endpoints are commonly exposed."),
    "jenkins": (Severity.HIGH, "Jenkins without auth exposes build/credential surfaces."),
}

_REPORTED_TECH = ["wordpress", "phpmyadmin", "drupal", "joomla", "moodle", "tomcat", "jenkins"]


def parse_whatweb_json(raw: str) -> dict[str, dict]:
    """Parse whatweb --log-json output into {target: plugin_map}."""
    out: dict[str, dict] = {}
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = rec.get("target") or ""
        if not target:
            continue
        out[target] = rec.get("plugins") or {}
    return out


def _platform(plugins: dict) -> list[str]:
    return [name.lower() for name in plugins if name.lower() in _REPORTED_TECH]


def _versions(plugins: dict) -> dict[str, str]:
    """Extract only explicit WhatWeb versions; never infer one from a product name."""
    versions: dict[str, str] = {}
    for name, values in plugins.items():
        if not isinstance(values, dict):
            continue
        version = values.get("version")
        if isinstance(version, list):
            version = next((str(item) for item in version if item), "")
        if isinstance(version, str) and version.strip():
            versions[name] = version.strip()
    return versions


def run(hosts: list[HostInfo], *, timeout: float = 90.0) -> ModuleResult:
    """Fingerprint web technologies on responding hosts with whatweb."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    path = which("whatweb")
    targets = [h.url for h in hosts if 200 <= h.status <= 399]
    if not targets:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No fingerprintable candidates",
                detail="No HTTP 2xx/3xx host to run whatweb against.",
                recommendation="",
            )
        )
        return result
    if not path:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="whatweb not available",
                detail="Technology detection skipped: whatweb not found on PATH.",
                recommendation="Install whatweb (apt install whatweb) or rely on httpx -tech-detect.",
            )
        )
        return result

    with temporary_output(prefix="uncp_offsec_whatweb_", suffix=".json") as outfile:
        result_tool = run_tool([path, "-q", "--log-json", outfile, *targets], timeout=timeout)
        parsed_text = Path(outfile).read_text(errors="replace") if Path(outfile).exists() else ""
    if not result_tool.ok:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Technology detection incomplete",
                detail=f"whatweb exited with rc={result_tool.returncode}.\n{result_tool.stderr.strip()[:300]}",
                recommendation="",
            )
        )
        # Fall back to what httpx already reported.
        hosts_with_tech = [h for h in hosts if h.tech]
        if hosts_with_tech:
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.INFO,
                    title="Technologies reported by httpx",
                    detail="\n".join(
                        f"{h.url}: {', '.join(h.tech)}" for h in hosts_with_tech
                    ),
                    recommendation="",
                )
            )
        return result

    parsed = parse_whatweb_json(parsed_text)
    if not parsed:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No technologies fingerprinted",
                detail="whatweb did not return any plugin matches for the targets.",
                recommendation="",
            )
        )
        return result

    summary = []
    platforms = []
    for target, plugins in sorted(parsed.items()):
        names = sorted(set(plugins.keys()))
        summary.append(f"{target}: {', '.join(names[:12])}")
        platforms.extend(_platform(plugins))
        normalized = target.rstrip("/")
        for host in hosts:
            if host.url.rstrip("/") == normalized:
                host.tech_versions.update(_versions(plugins))
                break

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title=f"Technologies fingerprinted on {len(parsed)} targets",
            detail="\n".join(summary),
            recommendation="",
        )
    )

    seen: set[str] = set()
    for platform in sorted(set(platforms)):
        if platform in seen:
            continue
        seen.add(platform)
        sev, note = _RISKY_TECH[platform]
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=sev,
                title=f"{platform} detected",
                detail=f"Platform fingerprint found on: {', '.join(sorted({t for t in parsed if platform in _platform(parsed[t])}))}",
                recommendation=note,
            )
        )

    return result
