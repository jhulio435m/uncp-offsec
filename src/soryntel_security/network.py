"""Internal-network assessment inside an explicitly authorized private range.

Same boundary as the rest of the tool: discover, identify and report. Hosts are
found with an Nmap ping scan, their TCP ports with naabu and the services behind
them with Nmap service detection and the closed list of inventory scripts. No
credentials are tried and nothing is exploited.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from collections.abc import Callable

from mailsec.models import Finding, ModuleResult, Severity

from .models import HostInfo, WebScanResult
from .scope import AuthorizationScope, allows_ip
from .web import nmap as nmap_mod
from .web import ports as ports_mod
from .web.scoring import compute_coverage, compute_web_score
from .web.tools import run as run_tool
from .web.tools import which

MODULE_NAME = "network_discovery"
# Without discovery every address is port-scanned, so the batch stays small.
NO_DISCOVERY_MAX_HOSTS = 64


def expand_targets(targets: list[str] | tuple[str, ...], scope: AuthorizationScope) -> list[str]:
    """Return the individual addresses named by targets, all inside the scope.

    Raises ValueError when a target is malformed, public, outside the authorized
    networks, or when the total exceeds the scope's host limit.
    """
    if not scope.networks:
        raise ValueError("the scope file authorizes no internal networks ('networks' is empty)")
    addresses: dict[ipaddress.IPv4Address | ipaddress.IPv6Address, None] = {}
    for raw in targets:
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"'{raw}' is not an IP address or CIDR range") from exc
        if not network.is_private:
            raise ValueError(f"{network} is not a private range; internal mode only assesses private networks")
        if not any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in map(ipaddress.ip_network, scope.networks)
        ):
            raise ValueError(f"{network} is outside the networks authorized by scope '{scope.name}'")
        # hosts() is lazy: a huge range stops at the scope limit instead of being built in memory.
        hosts = [network.network_address] if network.num_addresses == 1 else network.hosts()
        for address in hosts:
            addresses[address] = None
            if len(addresses) > scope.network_max_hosts:
                raise ValueError(
                    f"targets exceed the scope limit of {scope.network_max_hosts} addresses; "
                    "assess a smaller range or raise 'network_max_hosts' in the scope"
                )
    resolved = [str(address) for address in sorted(addresses, key=lambda item: (item.version, int(item)))]
    outside = [address for address in resolved if not allows_ip(scope, address)]
    if outside:  # Defensive: subnet_of() above already guarantees this.
        raise ValueError(f"addresses outside the authorized networks: {', '.join(outside[:5])}")
    return resolved


def parse_ping_scan(raw: str) -> list[str]:
    """Return the addresses an Nmap -sn XML report marks as up."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    live = []
    for host in root.findall("host"):
        status = host.find("status")
        address = host.find("address")
        if status is not None and status.get("state") == "up" and address is not None and address.get("addr"):
            live.append(str(address.get("addr")))
    return live


def discover(addresses: list[str], *, timeout: float | None = 300.0) -> tuple[ModuleResult, list[str]]:
    """Find which authorized addresses respond, without touching their services."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=0.0)
    path = which("nmap")
    if not path:
        result.assessed = False
        result.findings.append(Finding(
            module=MODULE_NAME, severity=Severity.INFO, title="Nmap not available",
            detail="Host discovery skipped: nmap not found on PATH.",
            recommendation="Install Nmap, or rerun with --no-discovery on a small range.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
        return result, []
    tool = run_tool([path, "-sn", "-n", "-oX", "-", *addresses], timeout=timeout)
    live = [address for address in parse_ping_scan(tool.stdout) if address in set(addresses)]
    if not tool.ok and not live:
        result.assessed = False
        result.findings.append(Finding(
            module=MODULE_NAME, severity=Severity.INFO, title="Host discovery incomplete",
            detail=f"nmap rc={tool.returncode}.\n{(tool.stderr or '').strip()[:400]}",
            recommendation="Repeat discovery on a smaller range.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
        return result, []
    result.findings.append(Finding(
        module=MODULE_NAME, severity=Severity.INFO,
        title=f"{len(live)} of {len(addresses)} authorized addresses responded",
        detail="\n".join(live) or "No address answered the discovery probes.",
        recommendation="Addresses that did not respond were not assessed; a host that drops probes can still be running.",
        confidence="MEDIUM",
    ))
    return result, live


def run_network(
    targets: list[str] | tuple[str, ...],
    scope: AuthorizationScope,
    *,
    top_ports: int = 1000,
    discovery: bool = True,
    on_progress: Callable[[str, float], None] | None = None,
) -> WebScanResult:
    """Assess the authorized internal addresses: who responds, what is open, what runs there."""
    if not scope.allow_active:
        raise ValueError("internal assessment sends probes; the scope must set 'allow_active': true")
    addresses = expand_targets(targets, scope)
    if not discovery and len(addresses) > NO_DISCOVERY_MAX_HOSTS:
        raise ValueError(f"--no-discovery is limited to {NO_DISCOVERY_MAX_HOSTS} addresses")

    def tick(stage: str, fraction: float) -> None:
        if on_progress is not None:
            on_progress(stage, fraction)

    modules: dict[str, ModuleResult] = {}
    tick("network_discovery", 0.05)
    if discovery:
        modules[MODULE_NAME], live = discover(addresses)
    else:
        live = addresses
        modules[MODULE_NAME] = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=0.0)
        modules[MODULE_NAME].findings.append(Finding(
            module=MODULE_NAME, severity=Severity.INFO, title="Host discovery skipped",
            detail=f"All {len(addresses)} authorized addresses were port-scanned.", recommendation="",
        ))

    hosts = [HostInfo(url="", host=address, ip=address) for address in live]
    tick("ports", 0.35)
    modules["ports"] = ports_mod.run(hosts, top_ports=top_ports, timeout=None)
    entries = getattr(modules["ports"], "open_ports", [])
    tick("nmap", 0.65)
    # Per-host limit: service detection plus inventory scripts on every open port.
    busiest = max((sum(1 for entry in entries if entry["host"] == host) for host in {e["host"] for e in entries}), default=0)
    modules["nmap"] = nmap_mod.run(
        entries, safe_scripts=True, vuln_scripts=scope.allow_nmap_vuln,
        timeout=float(min(900, 120 + 30 * busiest)),
    )
    ports_mod.reconcile_services(modules["ports"], modules["nmap"])
    tick("report", 0.95)

    breakdown = compute_web_score(modules)
    coverage = compute_coverage(modules)
    assessed = all(modules[name].assessed for name in ("ports", "nmap"))
    result = WebScanResult(
        domain=", ".join(str(target).strip() for target in targets),
        modules=[modules[MODULE_NAME], modules["ports"], modules["nmap"]],
        total_score=breakdown.total,
        # A score needs evidence: with no responding host or an unfinished port
        # scan there is nothing to rate.
        risk_level=breakdown.risk_level if live and modules["ports"].assessed else "INCONCLUSIVE",
        coverage_score=coverage,
        confidence="HIGH" if assessed and modules[MODULE_NAME].assessed else "LOW",
        target_mode="internal-network",
    )
    result.breakdown = breakdown  # type: ignore[attr-defined]
    return result
