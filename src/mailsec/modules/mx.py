"""MX record resolution and mailbox provider detection."""

from __future__ import annotations

import dns.resolver
from dns.exception import DNSException

from ..constants import RFC
from ..models import Finding, ModuleResult, MXInfo, ScanConfig, Severity

MODULE_NAME = "mx"
MAX_SCORE = 0.0


def run(config: ScanConfig) -> tuple[ModuleResult, list[MXInfo]]:
    """Resolve MX records for a domain and return the module result + MX list."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    mx_hosts: list[MXInfo] = []

    try:
        answers = dns.resolver.resolve(config.domain, "MX", lifetime=config.timeout)
    except dns.resolver.NXDOMAIN:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="Domain does not resolve (NXDOMAIN)",
                detail=f"The domain {config.domain} does not exist in DNS.",
                recommendation="Verify the domain is correctly registered and published.",
                rfc_ref=RFC["SMTP"],
            )
        )
        return result, mx_hosts
    except DNSException as e:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="MX lookup failed",
                detail=f"DNS query for MX records returned an error: {e.__class__.__name__}",
                recommendation="Ensure MX records exist and are resolvable.",
                rfc_ref=RFC["SMTP"],
            )
        )
        return result, mx_hosts

    if not answers:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="No MX records found",
                detail="The domain has no MX records, so it cannot receive email.",
                recommendation="Publish MX records pointing to the primary mail gateway.",
                rfc_ref=RFC["SMTP"],
            )
        )
        return result, mx_hosts

    mx_hosts = [MXInfo(hostname=str(r.exchange).rstrip("."), preference=r.preference) for r in answers]
    mx_hosts.sort(key=lambda m: m.preference)

    providers = {m.provider for m in mx_hosts}
    if len(providers) == 1 and providers != {"Custom/Unknown"}:
        provider = providers.pop()
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"Mail hosted by {provider}",
                detail=f"Primary provider detected: {provider}. "
                "Third-party providers usually enforce their own authentication defaults.",
                recommendation="Ensure provider-level SPF/DKIM/DMARC defaults align with policy.",
                rfc_ref=RFC["SMTP"],
            )
        )
    else:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"{len(mx_hosts)} MX record(s) found",
                detail="Multiple mail routes detected: " + ", ".join(m.hostname for m in mx_hosts),
                recommendation="Confirm all listed MX hosts are legitimate mail gateways.",
                rfc_ref=RFC["SMTP"],
            )
        )

    if len(mx_hosts) > 1:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="Redundant MX configuration",
                detail=f"{len(mx_hosts)} MX records provide failover capacity.",
                recommendation="",
                rfc_ref="",
            )
        )

    return result, mx_hosts
