"""MTA-STS (RFC 8461) analysis: DNS record + policy fetch/validation via HTTPS."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

import dns.resolver
from dns.exception import DNSException

from ..constants import RFC
from ..models import Finding, ModuleResult, ScanConfig, Severity

MODULE_NAME = "mta_sts"
MAX_SCORE = 10.0

VALID_MODES = {"enforce", "testing", "none"}
MAX_POLICY_SIZE = 64 * 1024


def _resolve_mta_sts_record(config: ScanConfig) -> str | None:
    """Return the raw MTA-STS DNS TXT record, or None."""
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{config.domain}", "TXT", lifetime=config.timeout)
    except DNSException:
        return None

    record = ""
    for r in answers:
        if r.rdtype == 16:
            for s in r.strings:
                txt = s.decode(errors="ignore").strip()
                if txt.lower().startswith(("v=stsv1", "v=sts1")):
                    record = txt
                    break
        if record:
            break
    return record or None


def _fetch_policy(config: ScanConfig) -> tuple[str | None, str | None]:
    """Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt.
    Returns (policy_text, failure_reason)."""
    url = f"https://mta-sts.{config.domain}/.well-known/mta-sts.txt"
    ctx = ssl.create_default_context()
    if not config.verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "MailSec-Auditor/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=config.timeout, context=ctx) as resp:
            body = resp.read(MAX_POLICY_SIZE + 1).decode(errors="ignore")
            return body, None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code} from {url}"
    except (urllib.error.URLError, ssl.SSLError, OSError) as e:
        return None, f"Fetch failed: {e}"


def _parse_policy(text: str) -> dict:
    parsed: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        parsed.setdefault(key, []).append(value)
    return parsed


def run(config: ScanConfig) -> ModuleResult:
    """Analyze MTA-STS configuration for the target domain."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)

    dns_record = _resolve_mta_sts_record(config)

    if dns_record is None:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="MTA-STS not configured",
                detail=f"No _mta-sts.{config.domain} TXT record. STARTTLS is opportunistic; "
                "active attackers can strip STARTTLS unless DANE is enforced.",
                recommendation="Publish a v=STSv1 record and a policy under "
                "https://mta-sts.<domain>/.well-known/mta-sts.txt. Start with mode: testing, "
                "then switch to enforce.",
                rfc_ref=RFC["MTA_STS"],
            )
        )
        return result

    policy, fetch_error = _fetch_policy(config)

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title="MTA-STS DNS record found",
            detail=f"Record: {dns_record}",
            recommendation="",
            rfc_ref=RFC["MTA_STS"],
        )
    )

    if fetch_error:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="MTA-STS policy fetch failed",
                detail=fetch_error,
                recommendation="Host a valid policy at mta-sts.<domain>/.well-known/mta-sts.txt. "
                "Use valid HTTPS with a trusted certificate.",
                rfc_ref=RFC["MTA_STS"],
            )
        )
        return result

    policy_dict = _parse_policy(policy)

    if "version" not in policy_dict or policy_dict["version"][0] != "STSv1":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="MTA-STS policy missing version: STSv1",
                detail="The policy file must start with version: STSv1.",
                recommendation="Add 'version: STSv1' as the first line.",
                rfc_ref=RFC["MTA_STS"],
            )
        )

    mode = policy_dict.get("mode", [""])[0].lower()
    if mode == "enforce":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="MTA-STS mode: enforce",
                detail="Receiving servers must offer TLS with a valid certificate from the mx: list.",
                recommendation="",
                rfc_ref=RFC["MTA_STS"],
            )
        )
    elif mode == "testing":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="MTA-STS mode: testing",
                detail="Policy is evaluated but not enforced; failures are only reported via TLS-RPT.",
                recommendation="Migrate to enforce once no TLS failures are reported.",
                rfc_ref=RFC["MTA_STS"],
            )
        )
    elif mode == "none":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="MTA-STS mode: none",
                detail="Policy states TLS is not enforced.",
                recommendation="Set mode to testing, then enforce.",
                rfc_ref=RFC["MTA_STS"],
            )
        )
    else:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title=f"MTA-STS invalid mode: {mode or '(empty)'}",
                detail="Valid modes are enforce, testing, none.",
                recommendation="Correct the mode field.",
                rfc_ref=RFC["MTA_STS"],
            )
        )

    mx_lines = policy_dict.get("mx", [])
    if not mx_lines:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="MTA-STS policy has no mx: entries",
                detail="The policy must list at least one MX host.",
                recommendation="Add mx: lines matching the actual MX records.",
                rfc_ref=RFC["MTA_STS"],
            )
        )

    try:
        max_age = int(policy_dict.get("max_age", [""])[0])
    except ValueError:
        max_age = 0
    if max_age <= 0:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="MTA-STS invalid max_age",
                detail="max_age must be a positive integer (seconds).",
                recommendation="Set max_age to at least 86400.",
                rfc_ref=RFC["MTA_STS"],
            )
        )
    elif max_age < 86400:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title=f"MTA-STS max_age={max_age} (memory retention short)",
                detail="A short max_age reduces the protection window.",
                recommendation="Use max_age: 604800 or higher.",
                rfc_ref=RFC["MTA_STS"],
            )
        )
    else:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title=f"MTA-STS max_age={max_age}",
                detail="",
                recommendation="",
                rfc_ref="",
            )
        )

    if policy_dict.get("id"):
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"MTA-STS policy id: {policy_dict['id'][0][:32]}",
                detail="id is used by senders to detect policy changes.",
                recommendation="",
                rfc_ref=RFC["MTA_STS"],
            )
        )

    return result