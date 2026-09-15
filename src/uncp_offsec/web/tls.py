"""TLS analysis for web endpoints via testssl.sh (the canonical TLS checker)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mailsec.models import Finding, Severity

from .tools import run, temporary_output

MODULE_NAME = "tls"
MAX_SCORE = 40.0

# protocol/vuln ids we call out explicitly, keyed by name.
_FLAGGED_IDS = {
    "SSLv2": Severity.CRITICAL,
    "SSLv3": Severity.CRITICAL,
    "TLS1": Severity.HIGH,
    "TLS1_1": Severity.HIGH,
    "heartbleed": Severity.CRITICAL,
    "poodle": Severity.HIGH,
    "poodle_tls": Severity.HIGH,
    "drown": Severity.CRITICAL,
    "logjam": Severity.HIGH,
    "freak": Severity.HIGH,
    "beast": Severity.LOW,
    "crime": Severity.LOW,
    "breach": Severity.MEDIUM,
    "robot": Severity.MEDIUM,
    "sessionTicket": Severity.LOW,
}

# testssl severity strings -> unified Severity
_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "VULNERABLE": Severity.HIGH,
    "WARN": Severity.INFO,
}

_CERT_IDS = {"cert_expirationStatus", "cert_startTime", "cert_expiration_time"}


def parse_testssl_json(text: str) -> list[dict]:
    """Extract testssl.sh entries with an id/severity/finding triple.

    Modern testssl writes a nested structure; older versions wrote one object
    per line. Both are handled here.
    """
    entries: list[dict] = []

    def collect(obj) -> None:
        if isinstance(obj, dict):
            if {"id", "severity", "finding"} <= set(obj.keys()):
                entries.append(obj)
            for value in obj.values():
                collect(value)
        elif isinstance(obj, list):
            for value in obj:
                collect(value)

    try:
        collect(json.loads(text))
        if entries:
            return entries
    except json.JSONDecodeError:
        pass

    # Fallback: line-based output (older testssl).
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if line.startswith("["):
            line = line[1:].strip()
        if line.endswith("]"):
            line = line[:-1].strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "id" in rec and "severity" in rec:
            entries.append(rec)
    return entries


def _severity(entry: dict) -> Severity | None:
    raw = str(entry.get("severity") or "").upper()
    if raw in ("OK", "INFO", "NONE"):
        return None
    return _SEV_MAP.get(raw)


def _openssl_probe(host: str, port: int = 443) -> list[Finding]:
    """Quick cert/protocol snapshot via openssl when testssl cannot finish."""
    findings: list[Finding] = []
    tool = run(
        [
            "sh", "-c",
            (
                f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null "
                f"| openssl x509 -noout -dates -subject 2>/dev/null; "
                f"echo '==protocol=='; "
                f"echo | openssl s_client -brief -connect {host}:{port} -servername {host} 2>/dev/null"
            ),
        ],
        timeout=30,
    )
    if not tool.ok:
        return findings
    body, _, brief = tool.stdout.partition("==protocol==")
    protocol = next((ln.split(":", 1)[1].strip() for ln in brief.splitlines()
                     if ln.startswith("Protocol version") and ":" in ln), "")
    not_after = next((ln.split("=", 1)[1].strip() for ln in body.splitlines()
                      if ln.startswith("notAfter=")), "")
    subject = next((ln.split("=", 1)[1].strip() for ln in body.splitlines()
                    if ln.startswith("subject=")), "")

    detail_bits = []
    if protocol:
        detail_bits.append(f"Protocol: {protocol}")
    if subject:
        detail_bits.append(f"Cert subject: {subject}")
    if not_after:
        detail_bits.append(f"Valid until: {not_after}")

    if not detail_bits:
        return findings
    sev = Severity.INFO
    title = f"TLS snapshot for {host} (openssl fallback)"
    if not_after:
        try:
            parts = not_after.split()
            if parts and parts[-1] == "GMT":
                parts = parts[:-1]
            expire = datetime.strptime(" ".join(parts), "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            days = (expire - datetime.now(timezone.utc)).days
            detail_bits.append(f"Days until expiry: {days}")
            if days < 0:
                sev = Severity.CRITICAL
                title = f"TLS certificate EXPIRED on {host}"
            elif days < 30:
                sev = Severity.HIGH
                title = f"TLS certificate expires soon on {host} ({days}d)"
        except ValueError:
            pass
    findings.append(
        Finding(
            module=MODULE_NAME,
            severity=sev,
            title=title,
            detail="\n".join(detail_bits),
            recommendation="Keep the certificate valid; renew before expiry.",
        )
    )
    return findings


def analyze_host(host: str, *, timeout: float | None = 150.0) -> tuple[list[Finding], list[str]]:
    """Run testssl.sh against one https host; return (findings, protocol_list)."""
    findings: list[Finding] = []
    protocols: list[str] = []
    badge = f"[{host}] "
    with temporary_output(prefix="uncp_offsec_testssl_", suffix=".json") as outfile:
        tool = run(
            [
                "testssl.sh", "--quiet", "--fast", "--jsonfile-pretty", outfile,
                f"https://{host}",
            ],
            timeout=timeout,
        )
        text = Path(outfile).read_text(errors="replace") if Path(outfile).exists() else ""
    entries = parse_testssl_json(text)

    if not entries:
        probes = _openssl_probe(host)
        if tool.timed_out:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title=f"testssl.sh timed out for {host} after {float(timeout):.0f}s",
                    detail="Applied a quick openssl fallback probe instead of the full TLS scan.",
                    recommendation="Re-run the TLS scan during off-peak hours or against a staging copy.",
                )
            )
        elif not tool.ok:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title=f"TLS check failed for {host}",
                    detail=f"testssl.sh rc={tool.returncode}.\n{tool.stderr.strip()[:300]}",
                    recommendation="",
                )
            )
        else:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.INFO,
                    title=f"testssl.sh returned no parseable data for {host}",
                    detail="Applied a quick openssl fallback probe.",
                    recommendation="",
                )
            )
        findings.extend(probes)
        return findings, protocols

    for e in entries:
        eid = e.get("id")
        raw = str(e.get("finding") or "")
        lowered = raw.lower()
        offered = "offered" in lowered and "not offered" not in lowered
        if eid in _FLAGGED_IDS:
            if eid in ("SSLv2", "SSLv3", "TLS1", "TLS1_1") and offered:
                sev = _FLAGGED_IDS[eid]
                protocols.append(eid)
                name = {"TLS1": "TLS 1.0", "TLS1_1": "TLS 1.1"}.get(eid, eid)
                findings.append(
                    Finding(
                        module=MODULE_NAME,
                        severity=sev,
                        title=f"{name} enabled on {host}",
                        detail=f"{raw}",
                        recommendation="Disable TLS 1.0/1.1 and older protocols; keep TLS 1.2/1.3.",
                    )
                )
            elif eid in _CERT_IDS and "expired" in lowered:
                findings.append(
                    Finding(
                        module=MODULE_NAME,
                        severity=Severity.HIGH,
                        title=f"Expired TLS certificate on {host}",
                        detail=f"{raw}",
                        recommendation="Renew the certificate before it breaks clients.",
                    )
                )

    # Summarize remaining problem severities for the host.
    buckets: dict[str, list[str]] = {}
    for e in entries:
        eid = e.get("id")
        sev = _severity(e)
        if sev is None or eid in (set(_FLAGGED_IDS) | set(_CERT_IDS)):
            continue
        buckets.setdefault(sev.value, []).append(f"{eid}: {str(e.get('finding'))[:90]}")
    for sev_value in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        entries_list = buckets.get(sev_value, [])
        if not entries_list:
            continue
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity[sev_value],
                title=badge + f"{len(entries_list)} TLS {sev_value} issue(s)",
                detail="\n".join(entries_list[:8]),
                recommendation="Review and remediate TLS configuration; follow current hardening guidance.",
            )
        )

    return findings, protocols
