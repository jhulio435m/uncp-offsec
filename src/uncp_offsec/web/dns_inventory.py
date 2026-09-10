"""Structured DNS inventory for discovered assets."""

from __future__ import annotations

import dns.exception
import dns.resolver

from mailsec.models import Finding, ModuleResult, Severity

MODULE_NAME = "dns_inventory"


def _query(host: str, record_type: str, timeout: float) -> list[str]:
    try:
        return sorted(str(record).rstrip(".") for record in dns.resolver.resolve(host, record_type, lifetime=timeout))
    except dns.exception.DNSException:
        return []


def run(domain: str, subdomains: list[str], *, timeout: float = 3.0, limit: int = 150) -> tuple[ModuleResult, dict[str, dict[str, list[str]]]]:
    """Collect DNS records within a bounded inventory size."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=0.0)
    records: dict[str, dict[str, list[str]]] = {}
    for host in [domain, *[item for item in subdomains if item != domain]][:limit]:
        record_types = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA") if host == domain else ("A", "AAAA", "CNAME")
        found = {kind: values for kind in record_types if (values := _query(host, kind, timeout))}
        if found:
            records[host] = found
    result.assessed = True
    result.findings.append(Finding(module=MODULE_NAME, severity=Severity.INFO, title=f"DNS inventory for {len(records)} host(s)", detail=f"Queried up to {limit} assets; records are included in JSON and HTML.", recommendation="Review CNAME chains, stale records and public IPs against approved inventory."))
    return result, records
