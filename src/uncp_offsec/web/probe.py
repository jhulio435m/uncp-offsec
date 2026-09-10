"""Live host probing via httpx (ProjectDiscovery)."""

from __future__ import annotations

import json

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo
from .tools import run as run_tool
from .tools import temporary_list, which

MODULE_NAME = "live_hosts"
MAX_SCORE = 12.0

_SCHEME_PREF = {"https": 0, "http": 1}


def parse_httpx_json(lines: list[str]) -> list[HostInfo]:
    """Parse httpx -json output lines into HostInfo objects."""
    hosts: dict[str, HostInfo] = {}
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = rec.get("url") or ""
        if not url:
            continue
        host = rec.get("host") or url.split("://")[-1].split("/")[0]
        tech = sorted({str(t) for t in (rec.get("tech") or [])})
        hi = HostInfo(
            url=url,
            host=host,
            status=int(rec.get("status_code") or 0),
            title=(rec.get("title") or "")[:120],
            tech=tech,
            webserver=rec.get("webserver") or "",
            scheme=rec.get("scheme") or url.split("://")[0],
            ip=rec.get("ip") or (rec.get("a") or [""])[0],
            cdn=rec.get("cdn_name") or rec.get("cdn") or "",
        )
        # Keep the https variant of a given host when both schemes respond.
        prev = hosts.get(host)
        if prev is None or _SCHEME_PREF.get(hi.scheme, 9) < _SCHEME_PREF.get(prev.scheme, 9):
            hosts[host] = hi
    return sorted(hosts.values(), key=lambda h: (not h.status, h.host))


def _server_lines(hosts: list[HostInfo]) -> list[str]:
    return [
        f"{h.url}  [{h.status}] {h.title}".strip() + (f"  server={h.webserver}" if h.webserver else "")
        for h in hosts
    ]


def _dns_matches(target: str) -> bool:
    """Cheap existence check against the system resolver."""
    try:
        import dns.resolver

        dns.resolver.resolve(target, "A", lifetime=3)
        return True
    except Exception:
        return False


def _curl_probe(target: str, timeout: int) -> HostInfo | None:
    """Probe with curl when httpx cannot resolve; curl handles SNI/vhosts correctly."""
    for scheme in ("https", "http"):
        out = run_tool(
            [
                "curl", "-sk", "-o", "/dev/null", "-L", "--max-redirs", "5",
                "-m", str(timeout),
                "-w", "%{url_effective} %{http_code} %{content_type}",
                f"{scheme}://{target}/",
            ],
            timeout=timeout + 5,
        )
        if not out.ok:
            continue
        parts = out.stdout.strip().rsplit(" ", 2)
        if len(parts) != 3:
            continue
        eff, code, _ctype = parts
        if not code.isdigit() or int(code) == 0:
            continue
        return HostInfo(host=target, url=eff, scheme=eff.split("://")[0], status=int(code), title="")
    return None


def _curl_fallback(targets: list[str], timeout: int, limit: int = 40) -> list[HostInfo]:
    """Detect live web endpoints with curl for hosts httpx failed to probe."""
    hosts: list[HostInfo] = []
    probed = 0
    for target in targets:
        if probed >= limit:
            break
        if not _dns_matches(target):
            continue
        probed += 1
        hi = _curl_probe(target, timeout)
        if hi is not None:
            hosts.append(hi)
    return sorted(hosts, key=lambda h: (not h.status, h.host))


def run(
    domain: str,
    subdomains: list[str],
    *,
    timeout: float = 60.0,
    resolvers: str | None = None,
) -> tuple[ModuleResult, list[HostInfo]]:
    """Probe discovered subdomains plus the apex for live HTTP(S) hosts."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    path = which("httpx")
    if not path:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="httpx not available",
                detail="Host probing skipped: httpx binary not found on PATH.",
                recommendation="Install httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            )
        )
        return result, []

    targets = sorted({domain, *subdomains})

    with temporary_list(targets, prefix="uncp_offsec_httpx_") as tmp:
        cmd = [
            path, "-l", tmp, "-silent", "-status-code", "-title", "-tech-detect",
            "-follow-redirects", "-max-redirects", "5", "-unsafe", "-json",
            "-timeout", str(int(timeout)),
        ]
        if resolvers:
            cmd.extend(["-r", resolvers])
        tool = run_tool(cmd, timeout=timeout * 2 + 30)

    if not tool.ok:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Host probing via httpx failed",
                detail=f"httpx exited with rc={tool.returncode}.\n{tool.stderr.strip()[:400]}",
                recommendation="Re-run the host probing step in isolation.",
            )
        )

    hosts = parse_httpx_json(tool.json_lines())
    if not hosts:
        hosts = _curl_fallback(targets, timeout=max(1, int(min(timeout, 30))))
        if not hosts:
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title="No live HTTP(S) hosts",
                    detail="httpx and curl fallback did not detect a reachable web endpoint for the scanned hosts.",
                    recommendation="Verify DNS resolves and that web services are listening on 80/443.",
                )
            )
            return result, []
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"{len(hosts)} live HTTP(S) hosts (curl fallback)",
                detail="httpx name resolution is unreliable in this environment; verified with curl.",
                recommendation="",
            )
        )
        return result, hosts

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title=f"{len(hosts)} live HTTP(S) hosts",
            detail="\n".join(_server_lines(hosts)),
            recommendation="",
        )
    )

    waf_blocked = [h for h in hosts if h.status in (403, 429, 503)]
    if waf_blocked:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"{len(waf_blocked)} host(s) limiting or blocking probes",
                detail="\n".join(f"{h.url}  [{h.status}]" for h in waf_blocked),
                recommendation=(
                    "Coverage is limited for these hosts. Respect the response, reduce rate or "
                    "obtain an approved WAF allowlist/testing window; do not attempt to bypass it."
                ),
            )
        )

    errors = [h for h in hosts if h.status >= 400]
    if errors and len(errors) <= len(hosts):
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title=f"{len(errors)} hosts returning HTTP error status",
                detail="\n".join(f"{h.url}  [{h.status}]" for h in errors),
                recommendation="Check which are intentionally erroring (auth-required) vs. broken endpoints.",
            )
        )

    return result, hosts
