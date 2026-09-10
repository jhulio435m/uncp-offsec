"""DANE (RFC 7672) analysis: TLSA records for SMTP port 25."""

from __future__ import annotations

import dns.resolver
from dns.exception import DNSException

from ..constants import RFC
from ..models import Finding, ModuleResult, MXInfo, ScanConfig, Severity

MODULE_NAME = "dane"
MAX_SCORE = 3.0

# Valid per RFC 7672/6698
VALID_USAGE = {0, 1, 2, 3}
# For SMTP: selectors 0 (cert) and 1 (SPKI) are allowed; 2/3 reserved
VALID_SELECTOR = {0, 1}
VALID_MATCHING = {0, 1, 2}

MATCHING_NAMES = {0: "full", 1: "sha256", 2: "sha512"}
USAGE_NAMES = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}
SELECTOR_NAMES = {0: "cert", 1: "spki"}


def _check_dnssec(config: ScanConfig) -> bool:
    """Heuristic DNSSEC check: does a DO-bit query succeed? Best-effort only."""
    try:
        import dns.message
        import dns.query
        import dns.rdatatype

        q = dns.message.make_query(config.domain, dns.rdatatype.A, want_dnssec=True)
        for server in dns.resolver.Resolver().nameservers[:2]:
            try:
                resp = dns.query.udp(q, server, timeout=config.timeout)
                if resp.answer and any(
                    r.rdtype == dns.rdatatype.RRSIG for r in resp.answer
                ):
                    return True
            except DNSException:
                continue
    except Exception:
        pass
    return False


def run(config: ScanConfig, mx_hosts: list[MXInfo]) -> ModuleResult:
    """Analyze DANE TLSA records for each MX host."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)

    if not mx_hosts:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No MX hosts to check for DANE",
                detail="",
                recommendation="",
                rfc_ref="",
            )
        )
        return result

    dnssec = _check_dnssec(config)

    found_tlsa = False
    for mx in mx_hosts:
        tlsa_name = f"_25._tcp.{mx.hostname}"
        try:
            answers = dns.resolver.resolve(tlsa_name, "TLSA", lifetime=config.timeout)
        except DNSException:
            continue
        found_tlsa = True
        for r in answers:
            if r.rdtype == 52:  # TLSA
                usage = getattr(r, "usage", None)
                selector = getattr(r, "selector", None)
                matching = getattr(r, "mtype", getattr(r, "matching_type", None))
                cert_data = r.cert.hex()
                problems: list[str] = []

                if usage not in VALID_USAGE:
                    problems.append(f"invalid usage={usage} ({USAGE_NAMES.get(usage, '?')})")
                if selector not in VALID_SELECTOR:
                    problems.append(f"invalid selector={selector}")
                if matching not in VALID_MATCHING:
                    problems.append(f"invalid matching type={matching}")

                detail_parts = [
                    f"usage={usage} ({USAGE_NAMES.get(usage, '?')})",
                    f"selector={selector} ({SELECTOR_NAMES.get(selector, '?')})",
                    f"matching={matching} ({MATCHING_NAMES.get(matching, '?')})",
                ]
                hash_issue = None
                if matching == 1 and len(r.cert) != 32:
                    hash_issue = "SHA-256 association should be 32 bytes."
                elif matching == 2 and len(r.cert) != 64:
                    hash_issue = "SHA-512 association should be 64 bytes."

                if problems:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.HIGH,
                            title=f"MX {mx.hostname}: malformed TLSA record",
                            detail="; ".join(detail_parts) + " | " + "; ".join(problems),
                            recommendation="Fix the TLSA record to DANE-EE SHA-256 per RFC 7672.",
                            rfc_ref=RFC["DANE"],
                        )
                    )
                elif hash_issue:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.LOW,
                            title=f"MX {mx.hostname}: TLSA hash length unusual",
                            detail=hash_issue,
                            recommendation="Regenerate the association.",
                            rfc_ref=RFC["DANE"],
                        )
                    )
                else:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.PASS,
                            title=f"MX {mx.hostname}: valid TLSA record",
                            detail="; ".join(detail_parts) + f"; key={cert_data[:24]}...",
                            recommendation="",
                            rfc_ref=RFC["DANE"],
                        )
                    )

    if not found_tlsa:
        dane_note = "DNSSEC is NOT detected for the domain." if not dnssec else "DNSSEC detected."
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="DANE/TLSA not configured",
                detail=f"No TLSA records published for any MX host. {dane_note} "
                "Without DANE, STARTTLS downgrade attacks remain possible (unless MTA-STS enforce).",
                recommendation="Publish DANE-EE TLSA records for each MX host, or rely on "
                "MTA-STS enforce as an alternative mitigation.",
                rfc_ref=RFC["DANE"],
            )
        )

    return result
