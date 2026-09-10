"""Vulnerability matching via nuclei (ProjectDiscovery), active by nature."""

from __future__ import annotations

import json

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo
from .tools import run as run_tool
from .tools import temporary_list, which

MODULE_NAME = "vulns"
MAX_SCORE = 18.0

_INFO_TAGS = {"exposure", "misconfiguration", "default-login", "tech"}
SAFE_TEMPLATE = "/opt/uncp-tools/nuclei-safe"


def parse_nuclei_json(lines: list[str]) -> list[dict]:
    """Parse nuclei -json output lines into normalized matches."""
    out = []
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info") or {}
        raw_tags = info.get("tags") or []
        if isinstance(raw_tags, str):
            tags = [tag.strip() for tag in raw_tags.split(",") if tag.strip()]
        elif isinstance(raw_tags, list):
            tags = [str(tag).strip() for tag in raw_tags if str(tag).strip()]
        else:
            tags = [str(raw_tags).strip()] if str(raw_tags).strip() else []
        sev_raw = str(info.get("severity") or "info").lower()
        sev = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "unknown": Severity.INFO,
        }.get(sev_raw, Severity.INFO)
        out.append(
            {
                "id": rec.get("template-id") or "",
                "name": str(info.get("name") or rec.get("template-id") or "match"),
                "severity": sev,
                "matched": rec.get("matched-at") or rec.get("host") or "",
                "tags": tags,
            }
        )
    return out


def run(
    hosts: list[HostInfo],
    *,
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: float = 900.0,
    resolvers: str | None = None,
    headers: dict[str, str] | None = None,
) -> ModuleResult:
    """Run nuclei templates against the live host list."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    path = which("nuclei")
    if not path:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="nuclei not available",
                detail="Vulnerability matching skipped: nuclei not found on PATH.",
                recommendation="Install nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            )
        )
        return result
    if not hosts:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No hosts for nuclei",
                detail="The probing step produced no live hosts.",
                recommendation="",
            )
        )
        return result

    with temporary_list([h.url for h in hosts], prefix="uncp_offsec_nuclei_") as tmp:
        cmd = [
            path,
            "-l",
            tmp,
            "-silent",
            "-jsonl",
            "-rl",
            str(rate_limit),
            "-c",
            str(concurrency),
            "-t",
            SAFE_TEMPLATE,
            "-disable-update-check",
        ]
        if resolvers:
            cmd.extend(["-r", resolvers])
        for name, value in (headers or {}).items():
            cmd.extend(["-H", f"{name}: {value}"])
        tool = run_tool(cmd, timeout=timeout)

    matches = parse_nuclei_json(tool.json_lines())
    if not tool.ok and not matches:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="nuclei run returned no usable data",
                detail=f"nuclei rc={tool.returncode}.\n{(tool.stderr or tool.stdout).strip()[:500]}",
                recommendation="",
            )
        )
        return result

    if not matches:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="No template matches",
                detail="nuclei did not match any vulnerability templates against the targets.",
                recommendation="",
            )
        )
        return result

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title=f"{len(matches)} nuclei template matches",
            detail="\n".join(
                f"{match['id']}: {match['name']} @ {match['matched']}"
                + (f" [tags: {', '.join(match['tags'][:6])}]" if match["tags"] else "")
                for match in matches
            ),
            recommendation="",
        )
    )

    actionable = [m for m in matches if m["severity"] not in (Severity.PASS, Severity.INFO)]
    by_sev: dict[Severity, list[dict]] = {}
    for m in actionable:
        by_sev.setdefault(m["severity"], []).append(m)

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        for m in by_sev.get(sev, []):
            detail = f"template={m['id']}\nmatched at: {m['matched']}"
            if m["tags"]:
                detail += f"\ntags: {', '.join(m['tags'][:6])}"
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=sev,
                    title=m["name"],
                    detail=detail,
                    recommendation="Review the nucleus finding against your authorization scope and patch/block accordingly.",
                )
            )

    return result
