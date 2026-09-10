"""SPF (Sender Policy Framework) analysis per RFC 7208."""

from __future__ import annotations

import re

import dns.resolver
from dns.exception import DNSException

from ..constants import RFC, SPF_MAX_DNS_LOOKUPS
from ..models import Finding, ModuleResult, ScanConfig, Severity

MODULE_NAME = "spf"
MAX_SCORE = 18.0


def _strip_quotes(value: str) -> str:
    return value.replace('"', "")


def _parse_spf(record: str) -> tuple[str | None, list[str] | None, str | None]:
    """Return (all_qualifier, include_terms, redirect_mechanism) from an SPF record."""
    record = record.strip().lower()
    if not record.startswith("v=spf1"):
        return None, None, None

    tokens = record.split()
    all_qualifier = None
    include_terms = []
    redirect = None
    for token in tokens[1:]:
        if token.startswith("include:"):
            include_terms.append(token.split(":", 1)[1])
        elif token.startswith("redirect="):
            redirect = token.split("=", 1)[1]
        elif re.match(r"^(\+|-|~|\?)?all$", token):
            all_qualifier = token[0] if token[0] in "+-~?" else "+"
    return all_qualifier, include_terms, redirect


def _count_lookups(include_terms: list[str]) -> int:
    """Recursively count DNS lookups including nested includes (bounded)."""
    total = len(include_terms)
    visited: set[str] = set()

    def count_includes(domain: str, depth: int):
        nonlocal total
        if depth > 6 or domain in visited:
            return
        visited.add(domain)
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
        except DNSException:
            return
        for r in answers:
            for s in r.strings:
                record = _strip_quotes(s.decode(errors="ignore"))
                if record.startswith("v=spf1"):
                    _, nested_includes, redirect = _parse_spf(record)
                    if nested_includes:
                        total += len(nested_includes)
                        for term in nested_includes:
                            count_includes(term, depth + 1)
                    if redirect:
                        total += 1
                        count_includes(redirect, depth + 1)

    for term in include_terms:
        count_includes(term, 0)
    return total


def run(config: ScanConfig) -> ModuleResult:
    """Analyze SPF record for the target domain."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)

    try:
        answers = dns.resolver.resolve(config.domain, "TXT", lifetime=config.timeout)
    except DNSException as e:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="SPF record not found or DNS failure",
                detail=f"Could not retrieve SPF: {e.__class__.__name__}. "
                "Without SPF, receiving servers must rely on other signals.",
                recommendation="Publish an SPF record. Example: v=spf1 include:_spf.provider.com -all",
                rfc_ref=RFC["SPF"],
            )
        )
        return result

    spf_record = None
    for r in answers:
        for s in r.strings:
            record = _strip_quotes(s.decode(errors="ignore"))
            if record.startswith("v=spf1"):
                spf_record = record
                break
        if spf_record:
            break

    if spf_record is None:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="No SPF record published",
                detail="The domain has no v=spf1 TXT record. Any mail server can spoof this "
                "domain as the envelope sender.",
                recommendation="Publish an SPF TXT record listing all authorized senders and end with -all.",
                rfc_ref=RFC["SPF"],
            )
        )
        return result

    all_qualifier, include_terms, redirect = _parse_spf(spf_record)

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title="SPF record found",
            detail=f"Record: {spf_record}",
            recommendation="",
            rfc_ref=RFC["SPF"],
        )
    )

    if all_qualifier == "-":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="Hard fail -all configured",
                detail="Unauthorized senders receive an SPF hard fail (FAIL).",
                recommendation="",
                rfc_ref=RFC["SPF"],
            )
        )
    elif all_qualifier == "~":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Soft fail ~all configured",
                detail="Unauthorized senders receive SOFTFAIL. Receiving servers may still "
                "deliver the message depending on local policy.",
                recommendation="Migrate toward -all once all legitimate senders are listed.",
                rfc_ref=RFC["SPF"],
            )
        )
    elif all_qualifier == "?":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="Neutral ?all configured",
                detail="SPF is present but effectively unenforced (NEUTRAL).",
                recommendation="Change the final qualifier to -all or ~all.",
                rfc_ref=RFC["SPF"],
            )
        )
    elif all_qualifier == "+":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="+all configured (all senders authorized)",
                detail="The SPF record authorizes every sender. SPF provides no protection.",
                recommendation="Replace +all with -all after documenting legitimate infrastructure.",
                rfc_ref=RFC["SPF"],
            )
        )
    else:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="SPF record missing final all mechanism",
                detail="The SPF record does not end in an all mechanism, leaving policy undefined.",
                recommendation="Append -all (or ~all) to the end of the record.",
                rfc_ref=RFC["SPF"],
            )
        )

    if redirect and not all_qualifier:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"SPF redirect to {redirect}",
                detail="The record uses redirect=, delegating policy to another domain.",
                recommendation="Ensure the redirect target has a strict -all policy.",
                rfc_ref=RFC["SPF"],
            )
        )

    lookups = _count_lookups(include_terms) if (include_terms or redirect) else 0
    if lookups > SPF_MAX_DNS_LOOKUPS:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title=f"SPF exceeds DNS lookup limit ({lookups}/{SPF_MAX_DNS_LOOKUPS})",
                detail="RFC 7208 limits SPF to 10 DNS lookups (including nested includes). "
                "Overshoot causes PERMERROR on receiving servers.",
                recommendation="Flatten includes or consolidate third-party provider domains.",
                rfc_ref=RFC["SPF"],
            )
        )
    elif lookups > 0:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title=f"SPF DNS lookup count within limit ({lookups}/{SPF_MAX_DNS_LOOKUPS})",
                detail="",
                recommendation="",
                rfc_ref="",
            )
        )

    return result
