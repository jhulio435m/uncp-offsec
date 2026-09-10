"""DMARC analysis per RFC 9989 (supersedes RFC 7489)."""

from __future__ import annotations

import dns.resolver
from dns.exception import DNSException

from ..constants import RFC
from ..models import Finding, ModuleResult, ScanConfig, Severity

MODULE_NAME = "dmarc"
MAX_SCORE = 0.0  # Score is computed by risk_engine from dmarc policies

DMARC_POLICY_WEIGHT = {
    "none": 0,
    "quarantine": 1,
    "reject": 2,
}


def _parse_txt(record: str) -> dict:
    parsed = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            parsed[key.strip()] = value.strip()
    return parsed


def run(config: ScanConfig) -> tuple[ModuleResult, dict]:
    """Analyze DMARC record. Returns (module_result, policy_dict)."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    policy: dict = {}

    try:
        answers = dns.resolver.resolve(f"_dmarc.{config.domain}", "TXT", lifetime=config.timeout)
    except DNSException as e:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="No DMARC record published",
                detail=f"Could not resolve _dmarc.{config.domain} ({e.__class__.__name__}). "
                "Without DMARC, receiving servers cannot apply domain-level alignment policy "
                "and the domain is highly spoofable.",
                recommendation="Publish a DMARC record starting with p=none, add rua reporting, "
                "then enforce quarantine/reject once monitoring confirms legitimate traffic.",
                rfc_ref=RFC["DMARC"],
            )
        )
        return result, policy

    record = ""
    for r in answers:
        if r.rdtype == 16:
            for s in r.strings:
                txt = s.decode(errors="ignore")
                if txt.strip().startswith("v=DMARC1"):
                    record = txt
                    break
        if record:
            break

    if not record:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="No valid DMARC record found",
                detail="A TXT record exists at _dmarc but does not start with v=DMARC1.",
                recommendation="Publish a valid v=DMARC1 record.",
                rfc_ref=RFC["DMARC"],
            )
        )
        return result, policy

    policy = _parse_txt(record)
    p = policy.get("p", "").lower()
    sp = policy.get("sp", "").lower()
    pct = policy.get("pct", "100")
    rua = policy.get("rua", "").lower()
    ruf = policy.get("ruf", "").lower()
    adkim = policy.get("adkim", "r").lower()
    aspf = policy.get("aspf", "r").lower()

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title="DMARC record found",
            detail=f"Record: {record}",
            recommendation="",
            rfc_ref=RFC["DMARC"],
        )
    )

    if p == "reject":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="DMARC policy p=reject (strongest enforcement)",
                detail="Messages failing DMARC are rejected at the receiving edge.",
                recommendation="",
                rfc_ref=RFC["DMARC"],
            )
        )
    elif p == "quarantine":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="DMARC policy p=quarantine",
                detail="Messages failing DMARC are sent to spam/quarantine, not rejected.",
                recommendation="Migrate to p=reject once monitoring shows no legitimate failures.",
                rfc_ref=RFC["DMARC"],
            )
        )
    elif p == "none":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="DMARC policy p=none (monitoring only)",
                detail="failing DMARC receive no enforcement. The domain is still at risk of spoofing.",
                recommendation="Review aggregate reports, add legitimate senders, then escalate "
                "to p=quarantine and finally p=reject.",
                rfc_ref=RFC["DMARC"],
            )
        )

    try:
        pct_val = int(pct)
    except ValueError:
        pct_val = 100
    if pct_val < 100:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title=f"DMARC pct={pct_val} (partial enforcement)",
                detail="Only a percentage of failing messages receive the enforcement policy.",
                recommendation="Increase pct to 100 to apply policy to all traffic.",
                rfc_ref=RFC["DMARC"],
            )
        )

    if sp:
        if sp in ("reject", "quarantine"):
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"DMARC subdomain policy sp={sp}",
                    detail="Subdomains are explicitly covered by a non-none policy.",
                    recommendation="",
                    rfc_ref=RFC["DMARC"],
                )
            )
        elif sp == "none":
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title="DMARC subdomain policy sp=none",
                    detail="Subdomains are left unenforced and can be spoofed independently.",
                    recommendation="Set sp=reject (or sp=quarantine) to cover subdomains.",
                    rfc_ref=RFC["DMARC"],
                )
            )
    else:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="DMARC subdomain policy not set (inherits p=)",
                detail="Without sp=, subdomains inherit the organizational policy.",
                recommendation="",
                rfc_ref=RFC["DMARC"],
            )
        )

    if not rua:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="No DMARC aggregate reports (rua=) configured",
                detail="Without rua=, the org receives no visibility into who is sending as it.",
                recommendation="Add rua=mailto:<address> to enable aggregate reporting.",
                rfc_ref=RFC["DMARC_REPORT"],
            )
        )

    if not ruf:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="No DMARC failure reports (ruf=) configured",
                detail="Without ruf=, forensic failure reporting is disabled.",
                recommendation="Optionally add ruf=mailto:<address> with fo=1 for failure reports.",
                rfc_ref=RFC["DMARC_REPORT"],
            )
        )

    if adkim != "s":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"DKIM alignment adkim={adkim} (relaxed)",
                detail="Relaxed alignment allows the d= domain to differ from the envelope domain "
                "as long as both share the organizational domain.",
                recommendation="",
                rfc_ref=RFC["DMARC"],
            )
        )

    if aspf != "s":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"SPF alignment aspf={aspf} (relaxed)",
                detail="Relaxed SPF alignment is common and usually acceptable.",
                recommendation="",
                rfc_ref=RFC["DMARC"],
            )
        )

    return result, policy
