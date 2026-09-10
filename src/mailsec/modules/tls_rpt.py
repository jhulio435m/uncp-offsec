"""TLS-RPT (RFC 8460) analysis: _smtp._tls TXT record presence and format."""

from __future__ import annotations

import re

import dns.resolver
from dns.exception import DNSException

from ..constants import RFC
from ..models import Finding, ModuleResult, ScanConfig, Severity

MODULE_NAME = "tls_rpt"
MAX_SCORE = 4.0

MAILTO_RE = re.compile(r"^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)


def run(config: ScanConfig) -> ModuleResult:
    """Analyze TLS-RPT DNS configuration."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    fqdn = f"_smtp._tls.{config.domain}"

    try:
        answers = dns.resolver.resolve(fqdn, "TXT", lifetime=config.timeout)
    except DNSException:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="TLS-RPT not configured",
                detail=f"No {fqdn} TXT record. TLS failures (e.g. STARTTLS downgrades) will "
                "not be reported back to the organization.",
                recommendation="Publish a TLSRPT record pointing at an address that accepts "
                "the SMTP TLS reports: v=TLSRPTv1; rua=mailto:tls-report@yourdomain.com",
                rfc_ref=RFC["TLS_RPT"],
            )
        )
        return result

    record = ""
    for r in answers:
        if r.rdtype == 16:
            for s in r.strings:
                txt = s.decode(errors="ignore")
                if txt.lower().startswith("v=tlsrptv1"):
                    record = txt
                    break
        if record:
            break

    if not record:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="TLS-RPT record present but malformed",
                detail=f"A TXT record exists at {fqdn} but does not start with v=TLSRPTv1.",
                recommendation="Fix the record to v=TLSRPTv1; rua=mailto:...",
                rfc_ref=RFC["TLS_RPT"],
            )
        )
        return result

    rua_matches = re.findall(r"rua=([^;\s]+)", record, re.IGNORECASE)
    valid_rua = [m for m in rua_matches if MAILTO_RE.match(m)]

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title="TLS-RPT record found",
            detail=f"Record: {record}",
            recommendation="",
            rfc_ref=RFC["TLS_RPT"],
        )
    )

    if valid_rua:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="TLS-RPT reporting destination configured",
                detail="rua=" + ", ".join(valid_rua),
                recommendation="",
                rfc_ref=RFC["TLS_RPT"],
            )
        )
    else:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="TLS-RPT missing valid rua= mailto destination",
                detail="Reporting will not reach any address.",
                recommendation="Add rua=mailto:<address> to the record.",
                rfc_ref=RFC["TLS_RPT"],
            )
        )

    return result