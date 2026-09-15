"""Authorized, bounded URL and directory discovery via Katana and ffuf."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo
from .tools import run as run_tool
from .tools import temporary_list, temporary_output, which


def wordlist_tuning(wordlist: Path) -> tuple[int, int, int, int]:
    """Return (entries, rate, threads, estimated_seconds) for an approved list."""
    with wordlist.open("rb") as source:
        entries = sum(1 for line in source if line.strip() and not line.lstrip().startswith(b"#"))
    if entries <= 2_000:
        rate, threads = 10, 5
    elif entries <= 10_000:
        rate, threads = 8, 4
    else:
        rate, threads = 5, 2
    return entries, rate, threads, (entries + rate - 1) // rate


def crawl(
    hosts: list[HostInfo], *, limit: int = 200,
    headers: dict[str, str] | None = None, timeout: float | None = 180.0,
) -> tuple[ModuleResult, list[str]]:
    result = ModuleResult(name="crawl", score_contribution=0.0, max_score=0.0)
    path = which("katana")
    if not path or not hosts:
        result.assessed = False
        result.findings.append(Finding(module="crawl", severity=Severity.INFO, title="Katana unavailable or no live hosts", detail="", recommendation=""))
        return result, []
    with temporary_list([host.url for host in hosts[:20]], prefix="uncp_offsec_katana_") as targets:
        cmd = [path, "-list", targets, "-silent", "-d", "2", "-c", "5", "-rl", "5", "-jc", "-kf", "all"]
        for name, value in (headers or {}).items():
            cmd.extend(["-H", f"{name}: {value}"])
        tool = run_tool(cmd, timeout=timeout)
    allowed_hosts = {host.host.lower().rstrip(".") for host in hosts}
    all_urls = sorted(set(tool.lines()))
    urls = [
        url for url in all_urls
        if (urlparse(url).hostname or "").lower().rstrip(".") in allowed_hosts
    ][:limit]
    rejected = len(all_urls) - len(urls)
    result.assessed = tool.ok
    result.findings.append(Finding(
        module="crawl", severity=Severity.INFO,
        title=f"Katana retained {len(urls)} in-target URL(s)",
        detail="\n".join(urls),
        recommendation="Review the retained URLs as application coverage evidence.",
        confidence="HIGH", verification_status="OBSERVED",
    ))
    if rejected:
        result.findings.append(Finding(
            module="crawl", severity=Severity.INFO,
            title=f"Katana excluded {rejected} out-of-target URL(s)",
            detail="Links to hosts outside the initial target set were not passed to SQLi, anonymous-access, or ZAP modules.",
            recommendation="Run separate authorized exact-host scans for linked sibling applications when needed.",
            confidence="HIGH", verification_status="SCOPE_ENFORCED",
        ))
    if not tool.ok:
        reason = "authorized timeout" if tool.timed_out else f"exit code {tool.returncode}"
        result.findings.append(Finding(
            module="crawl", severity=Severity.INFO,
            title="Katana coverage incomplete",
            detail=f"Katana stopped because of {reason}; partial URLs were retained.",
            recommendation="Use --exact-host or divide a large inventory into smaller authorized batches.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
    return result, urls


def directories(
    hosts: list[HostInfo], *, wordlist: Path, limit: int = 200,
    headers: dict[str, str] | None = None, timeout: float | None = 180.0,
) -> ModuleResult:
    result = ModuleResult(name="content_discovery", score_contribution=0.0, max_score=0.0)
    path = which("ffuf")
    if not path or not hosts or not wordlist.is_file():
        result.assessed = False
        result.findings.append(Finding(module="content_discovery", severity=Severity.INFO, title="ffuf, wordlist or live hosts unavailable", detail="", recommendation="Provide an approved wordlist and ensure ffuf is installed."))
        return result
    rows: list[str] = []
    incomplete: list[str] = []
    completed = 0
    entries, rate, threads, estimated_seconds = wordlist_tuning(wordlist)
    for host in hosts[:10]:
        with temporary_output(prefix="uncp_offsec_ffuf_", suffix=".json") as output:
            cmd = [path, "-u", f"{host.url.rstrip('/')}/FUZZ", "-w", str(wordlist), "-mc", "200,204,301,302,307,308,401,403", "-ac", "-rate", str(rate), "-t", str(threads), "-s", "-of", "json", "-o", output]
            for name, value in (headers or {}).items():
                cmd.extend(["-H", f"{name}: {value}"])
            tool = run_tool(cmd, timeout=timeout)
            try:
                payload = json.loads(Path(output).read_text())
                rows.extend(str(item.get("url")) for item in payload.get("results", []) if item.get("url"))
            except (OSError, json.JSONDecodeError):
                pass
        if not tool.ok:
            reason = "timeout" if tool.timed_out else f"rc={tool.returncode}"
            incomplete.append(f"{host.url}: {reason}")
            continue
        completed += 1
    rows = sorted(set(rows))[:limit]
    result.assessed = completed > 0
    configuration = (
        f"Wordlist: {wordlist.name} ({entries} entries)\n"
        f"Rate: {rate} requests/s; workers: {threads}; estimated minimum per host: {estimated_seconds}s"
    )
    result.findings.append(Finding(module="content_discovery", severity=Severity.INFO, title=f"ffuf discovered {len(rows)} path(s)", detail=configuration + ("\n" + "\n".join(rows) if rows else ""), recommendation="Validate whether discovered administrative or backup paths should be restricted.", confidence="HIGH", verification_status="OBSERVED"))
    if incomplete:
        result.findings.append(Finding(module="content_discovery", severity=Severity.INFO, title="ffuf coverage limited", detail="\n".join(incomplete), recommendation="Use --exact-host, a target-specific wordlist, or a larger authorized execution window.", confidence="HIGH", verification_status="TOOL_INCOMPLETE"))
    return result
