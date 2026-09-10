"""Forensic analysis of a received .eml message."""

from __future__ import annotations

import email
import email.utils
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import RFC
from ..models import Finding, ModuleResult, ScanConfig, Severity

MODULE_NAME = "eml"
MAX_SCORE = 0.0

AUTHRES_RE = re.compile(r"\bdmarc=(none|pass|fail|policy|temperror|permerror)\b", re.IGNORECASE)
SPF_RE = re.compile(r"\bspf=(none|pass|fail|softfail|neutral|temperror|permerror)\b", re.IGNORECASE)
DKIM_RE = re.compile(r"\bdkim=(none|pass|fail|policy|temperror|permerror)\b", re.IGNORECASE)


@dataclass
class EMLAnalysis:
    subject: str = ""
    envelope_from: str = ""
    from_header: str = ""
    return_path: str = ""
    auth_results: list[str] = field(default_factory=list)
    received_chain: list[str] = field(default_factory=list)
    measured_spf: str = "unknown"
    measured_dkim: str = "unknown"
    measured_dmarc: str = "unknown"
    dmarc_disposition: str = "unknown"
    arc_results: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "envelope_from": self.envelope_from,
            "from_header": self.from_header,
            "return_path": self.return_path,
            "auth_results": self.auth_results,
            "received_chain": self.received_chain,
            "measured_spf": self.measured_spf,
            "measured_dkim": self.measured_dkim,
            "measured_dmarc": self.measured_dmarc,
            "dmarc_disposition": self.dmarc_disposition,
            "arc_results": self.arc_results,
        }


def _parse_authentication_results(raw: str, analysis: EMLAnalysis) -> None:
    """Parse Authentication-Results header(s)."""
    if not raw:
        return
    for line in re.split(r"\r?\n", raw):
        line = line.strip()
        if not line:
            continue
        # Skip continuation (leading tab/space)
        analysis.auth_results.append(line)

        m = SPF_RE.search(line)
        if m:
            analysis.measured_spf = m.group(1).lower()
        m = DKIM_RE.search(line)
        if m:
            analysis.measured_dkim = m.group(1).lower()
        m = AUTHRES_RE.search(line)
        if m:
            analysis.measured_dmarc = m.group(1).lower()
        dm_disp = re.search(
            r"(?:dmarc-disposition|dis)\s*=\s*(reject|quarantine|none)\b",
            line, re.IGNORECASE,
        )
        if dm_disp:
            analysis.dmarc_disposition = dm_disp.group(1).lower()


def analyze(path: Path, config: ScanConfig | None = None) -> tuple[EMLAnalysis, ModuleResult]:
    """Analyze an EML file. Returns analysis object + module result with findings."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    analysis = EMLAnalysis()

    if not path.exists():
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="EML file not found",
                detail=f"{path} does not exist.",
                recommendation="Provide a valid path to the .eml file.",
                rfc_ref="",
            )
        )
        return analysis, result

    try:
        msg = email.message_from_binary_file(path.open("rb"))
    except (OSError, ValueError) as e:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="Failed to parse EML",
                detail=str(e),
                recommendation="Verify the file is a well-formed RFC 5322 message.",
                rfc_ref=RFC["SMTP"],
            )
        )
        return analysis, result

    analysis.subject = str(msg.get("Subject", ""))
    analysis.envelope_from = str(msg.get("envelope-from", ""))
    analysis.from_header = str(msg.get("From", ""))
    analysis.return_path = str(msg.get("Return-Path", ""))

    _parse_authentication_results(
        msg.get("Authentication-Results", ""), analysis
    )

    analysis.received_chain = [h.strip() for h in msg.get_all("Received", [])]
    analysis.arc_results = [
        h.strip() for h in (msg.get_all("ARC-Authentication-Results", []) or [])
    ]

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title="Message metadata extracted",
            detail=(f"From: {analysis.from_header}\n"
                    f"Return-Path: {analysis.return_path}\n"
                    f"Subject: {analysis.subject}\n"
                    f"SPF={analysis.measured_spf} DKIM={analysis.measured_dkim} "
                    f"DMARC={analysis.measured_dmarc}"),
            recommendation="",
            rfc_ref="",
        )
    )

    # SPF
    if analysis.measured_spf == "fail":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="SPF authentication FAILED",
                detail="The envelope sender was not authorized by the domain's SPF record.",
                recommendation="Treat this message as suspicious; check DMARC disposition.",
                rfc_ref=RFC["SPF"],
            )
        )
    elif analysis.measured_spf == "softfail":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="SPF SOFTFAIL",
                detail="The envelope sender failed SPF but policy was ~all.",
                recommendation="Confirm sender legitimacy before trusting content.",
                rfc_ref=RFC["SPF"],
            )
        )
    elif analysis.measured_spf == "pass":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="SPF passed",
                detail="Envelope sender authorized by SPF.",
                recommendation="",
                rfc_ref="",
            )
        )

    # DKIM
    if analysis.measured_dkim == "fail":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="DKIM signature verification FAILED",
                detail="A DKIM signature was present but invalid (bad signature or key).",
                recommendation="Forge attempt or broken signing; escalate for inspection.",
                rfc_ref=RFC["DKIM"],
            )
        )
    elif analysis.measured_dkim == "pass":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="DKIM signature verified",
                detail="A signature validated against the advertised public key.",
                recommendation="",
                rfc_ref="",
            )
        )

    # DMARC
    dmarc_lower = analysis.measured_dmarc.lower()
    if dmarc_lower == "fail":
        severity = (
            Severity.CRITICAL
            if analysis.dmarc_disposition == "reject"
            else Severity.HIGH
        )
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=severity,
                title="DMARC authentication FAILED",
                detail=f"Message failed DMARC; disposition={analysis.dmarc_disposition}.",
                recommendation="Suppressed/rejected mail confirms spoofing attempt. ",
                rfc_ref=RFC["DMARC"],
            )
        )
    elif dmarc_lower == "pass":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.PASS,
                title="DMARC passed",
                detail="DKIM or SPF aligned with the From domain and passed.",
                recommendation="",
                rfc_ref="",
            )
        )
    elif dmarc_lower == "none":
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="No DMARC result recorded",
                detail="Authentication-Results does not carry a dmarc verdict.",
                recommendation="Confirm the receiving provider evaluates DMARC.",
                rfc_ref=RFC["DMARC"],
            )
        )

    # Return-path / From mismatch (spoofing heuristic)
    rp = analysis.return_path.strip("<> \t\r\n")
    from_domain = None
    _, faddr = email.utils.parseaddr(analysis.from_header)
    if "@" in faddr:
        from_domain = faddr.split("@", 1)[1].lower()
    rp_domain = rp.split("@", 1)[1].lower() if "@" in rp else None

    if from_domain and rp_domain and from_domain != rp_domain:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Return-Path domain differs from From domain",
                detail=f"Return-Path: {rp_domain} vs From: {from_domain}",
                recommendation="Verify DMARC/DKIM; mismatches are legitimate for some providers "
                "but frequent in phishing.",
                rfc_ref=RFC["SMTP"],
            )
        )

    # Received chain hop count
    if len(analysis.received_chain) > 3:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title=f"Unusually long Received chain ({len(analysis.received_chain)} hops)",
                detail="Many relays in the trace can indicate relay laundering or a mailing-list.",
                recommendation="Review each hop for legitimacy.",
                rfc_ref=RFC["SMTP"],
            )
        )

    # ARC
    if analysis.arc_results:
        last_arc = analysis.arc_results[-1]
        m = re.search(r"\barc=([a-z]+)\b", last_arc, re.IGNORECASE)
        if m:
            st = m.group(1).lower()
            if st == "pass":
                result.findings.append(
                    Finding(
                        module=MODULE_NAME,
                        severity=Severity.PASS,
                        title="ARC chain validated",
                        detail="Authenticated Received Chain (RFC 8617) preserved prior "
                        "authentication results.",
                        recommendation="",
                        rfc_ref=RFC["DKIM_ARC"],
                    )
                )
            elif st == "fail":
                result.findings.append(
                    Finding(
                        module=MODULE_NAME,
                        severity=Severity.HIGH,
                        title="ARC chain broken",
                        detail="The ARC chain is invalid; intermediate headers may have been forged.",
                        recommendation="Treat downstream Authentication-Results with caution.",
                        rfc_ref=RFC["DKIM_ARC"],
                    )
                )

    return analysis, result