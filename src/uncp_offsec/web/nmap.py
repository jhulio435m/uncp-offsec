"""Lightweight Nmap service identification for Naabu-confirmed ports."""

from __future__ import annotations

import re
import tempfile
import xml.etree.ElementTree as ET

from mailsec.models import Finding, ModuleResult, Severity

from .tools import run as run_tool
from .tools import which

SAFE_DISCOVERY_SCRIPTS = "banner,http-title,http-headers,ssl-cert,ssl-enum-ciphers"
# `vulners` correlates the version/CPE found by -sV with public CVE data. It does
# not deliver an exploit payload or attempt command execution.
IDENTIFICATION_ONLY_VULN_SCRIPTS = f"{SAFE_DISCOVERY_SCRIPTS},vulners"


def _script_severity(script_id: str, output: str) -> Severity:
    if "VULNERABLE" in output.upper():
        return Severity.HIGH
    if script_id == "vulners":
        scores = [float(value) for value in re.findall(r"\b(?:CVSS:)?(10(?:\.0)?|[0-9](?:\.[0-9])?)\b", output)]
        highest = max(scores, default=0.0)
        if highest >= 9.0:
            return Severity.CRITICAL
        if highest >= 7.0:
            return Severity.HIGH
        if highest >= 4.0:
            return Severity.MEDIUM
    return Severity.INFO


def parse_xml(raw: str) -> list[dict]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    rows = []
    for host in root.findall("host"):
        address = (host.find("address").get("addr") if host.find("address") is not None else "") or ""
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.get("state") != "open":
                continue
            scripts = [
                {"id": script.get("id", ""), "output": script.get("output", "")}
                for script in port.findall("script")
            ]
            rows.append({"host": address, "port": port.get("portid", ""), "service": (service.get("name") if service is not None else "") or "", "product": (service.get("product") if service is not None else "") or "", "version": (service.get("version") if service is not None else "") or "", "scripts": scripts})
    return rows


def run(entries: list[dict], *, safe_scripts: bool = False, vuln_scripts: bool = False) -> ModuleResult:
    """Identify services and optionally run bounded NSE script sets."""
    result = ModuleResult(name="nmap", score_contribution=0.0, max_score=0.0)
    path = which("nmap")
    if not path or not entries:
        result.assessed = False
        result.findings.append(Finding(module="nmap", severity=Severity.INFO, title="Nmap unavailable or no Naabu open ports", detail="", recommendation="Run --ports first and ensure Nmap is installed."))
        return result
    by_host: dict[str, set[str]] = {}
    aliases: dict[str, set[str]] = {}
    for entry in entries:
        ip = str(entry["host"])
        by_host.setdefault(ip, set()).add(str(entry["port"]))
        aliases.setdefault(ip, set()).add(str(entry["hostname"]))
    rows = []
    for host, ports in by_host.items():
        with tempfile.NamedTemporaryFile(suffix=".xml") as output:
            cmd = [path, "-n", "-sT", "-sV", "--version-light", "--host-timeout", "90s", "-Pn", "-p", ",".join(sorted(ports)), "-oX", output.name]
            if vuln_scripts:
                cmd.extend(["--script", IDENTIFICATION_ONLY_VULN_SCRIPTS, "--script-timeout", "20s"])
            elif safe_scripts:
                cmd.extend(["--script", SAFE_DISCOVERY_SCRIPTS, "--script-timeout", "20s"])
            tool = run_tool([*cmd, host], timeout=120)
            if tool.ok:
                for row in parse_xml(output.read().decode(errors="replace")):
                    row["aliases"] = ", ".join(sorted(aliases[host]))
                    rows.append(row)
    result.assessed = True
    result.findings.append(Finding(module="nmap", severity=Severity.INFO, title=f"Nmap identified {len(rows)} open service(s)", detail="\n".join(f"{row['host']} ({row.get('aliases', '')}):{row['port']} {row['service']} {row['product']} {row['version']}".strip() for row in rows), recommendation="Patch exposed service versions and restrict unintended services."))
    for row in rows:
        for script in row.get("scripts", []):
            output = str(script.get("output", ""))
            script_id = str(script.get("id", ""))
            severity = _script_severity(script_id, output)
            result.findings.append(Finding(module="nmap", severity=severity, title=f"NSE {script_id} on {row['host']}:{row['port']}", detail=output[:2000], recommendation="Validate the version/CVE correlation against the vendor advisory and patch or mitigate the affected service." if severity not in (Severity.INFO, Severity.PASS) else ""))
    return result
