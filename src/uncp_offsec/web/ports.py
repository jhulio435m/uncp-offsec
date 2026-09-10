"""Port scan via naabu (ProjectDiscovery) - TCP connect, active by nature."""

from __future__ import annotations

import json

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo
from .tools import run as run_tool
from .tools import temporary_list, which

MODULE_NAME = "ports"
MAX_SCORE = 12.0

# port -> (severity, label)
_PORT_MAP = {
    21: (Severity.LOW, "FTP"),
    22: (Severity.LOW, "SSH"),
    23: (Severity.HIGH, "Telnet (cleartext)"),
    25: (Severity.LOW, "SMTP"),
    80: (Severity.INFO, "HTTP"),
    110: (Severity.LOW, "POP3 (cleartext)"),
    111: (Severity.LOW, "RPCbind"),
    139: (Severity.MEDIUM, "SMB/NetBIOS"),
    143: (Severity.LOW, "IMAP (cleartext)"),
    161: (Severity.MEDIUM, "SNMP if public"),
    443: (Severity.INFO, "HTTPS"),
    445: (Severity.HIGH, "SMB"),
    1433: (Severity.MEDIUM, "MSSQL"),
    1521: (Severity.MEDIUM, "Oracle DB"),
    3306: (Severity.MEDIUM, "MySQL"),
    3389: (Severity.MEDIUM, "RDP"),
    5432: (Severity.MEDIUM, "PostgreSQL"),
    5900: (Severity.MEDIUM, "VNC"),
    5985: (Severity.MEDIUM, "WinRM"),
    6379: (Severity.MEDIUM, "Redis"),
    8000: (Severity.LOW, "Alt HTTP"),
    8080: (Severity.LOW, "Alt HTTP"),
    8081: (Severity.MEDIUM, "Alt HTTP (often proxies)"),
    8443: (Severity.LOW, "HTTPS-alternate"),
    8888: (Severity.MEDIUM, "Alt HTTP"),
    9000: (Severity.LOW, "App/panel"),
    9090: (Severity.MEDIUM, "Ops/panel"),
    9200: (Severity.HIGH, "Elasticsearch"),
    11211: (Severity.HIGH, "Memcached"),
    27017: (Severity.HIGH, "MongoDB"),
}


def parse_naabu_json(lines: list[str]) -> list[dict]:
    """Parse naabu -json output lines into {host, port, protocol} dicts."""
    out = []
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        port = rec.get("port")
        if port is None:
            continue
        host = rec.get("host") or rec.get("ip") or ""
        if not host:
            continue
        out.append(
            {
                "host": rec.get("ip") or host,
                "hostname": host,
                "port": int(port),
                "protocol": rec.get("protocol") or "tcp",
            }
        )
    return out


def run(
    hosts: list[HostInfo], *, top_ports: int = 1000, timeout: float = 300.0,
    resolvers: str | None = None,
) -> ModuleResult:
    """Scan live hosts for open TCP ports with naabu."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    path = which("naabu")
    if not path:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="naabu not available",
                detail="Port scanning skipped: naabu not found on PATH.",
                recommendation="Install naabu: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            )
        )
        return result
    if not hosts:
        result.assessed = False
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No hosts to port-scan",
                detail="The probing step produced no live hosts.",
                recommendation="",
            )
        )
        return result

    targets = sorted({h.ip or h.host for h in hosts})
    aliases: dict[str, set[str]] = {}
    for host in hosts:
        aliases.setdefault(host.ip or host.host, set()).add(host.host)
    with temporary_list(targets, prefix="uncp_offsec_naabu_") as tmp:
        cmd = [
            path, "-l", tmp, "-top-ports", str(top_ports),
            "-s", "c", "-Pn", "-ec", "-duc",
            "-rate", "500", "-timeout", "1000", "-retries", "1",
            "-silent", "-json",
        ]
        if resolvers:
            cmd.extend(["-r", resolvers])
        tool = run_tool(cmd, timeout=timeout)
    if not tool.ok:
        result.assessed = False
        reason = "authorized timeout" if tool.timed_out else f"exit code {tool.returncode}"
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Port scan incomplete",
                detail=f"Naabu stopped because of {reason}. Unique IP targets: {len(targets)}.\n{tool.stderr.strip()[:400]}",
                recommendation="Re-run against exact hosts or smaller IP batches; this is a coverage gap, not a vulnerability.",
                confidence="HIGH",
                verification_status="TOOL_INCOMPLETE",
            )
        )
        return result

    entries = parse_naabu_json(tool.json_lines())
    for entry in entries:
        names = aliases.get(entry["host"], aliases.get(str(entry.get("ip", "")), set()))
        if names:
            entry["hostname"] = ", ".join(sorted(names))
    result.open_ports = entries  # type: ignore[attr-defined]
    if not entries:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="No open TCP ports detected",
                detail="naabu found no open ports on the top-1000 range for the live hosts.",
                recommendation="",
            )
        )
        return result

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title=f"{len(entries)} open ports across {len({e['host'] for e in entries})} hosts",
            detail="\n".join(
                f"{e['hostname']}:{e['port']}/{e['protocol']}" for e in sorted(entries, key=lambda x: x["port"])
            ),
            recommendation="",
        )
    )

    flagged: dict[int, list[str]] = {}
    for e in entries:
        flag = _PORT_MAP.get(e["port"])
        if flag and flag[0] not in (Severity.PASS, Severity.INFO):
            flagged.setdefault(e["port"], []).append(e["hostname"])

    for port in sorted(flagged):
        sev, label = _PORT_MAP[port]
        targets = ", ".join(sorted(set(flagged[port]))[:12])
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=sev,
                title=f"Exposed {label} ({port}/tcp)",
                detail=f"Open on: {targets}",
                recommendation="Restrict to internal networks / VPN or close if unused.",
            )
        )

    return result
