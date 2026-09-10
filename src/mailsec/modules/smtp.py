"""SMTP handshake analysis: banner, EHLO, STARTTLS capability, software detection."""

from __future__ import annotations

import socket

from ..constants import RFC, SMTP_PORT
from ..models import Finding, ModuleResult, MXInfo, ScanConfig, Severity
from ..network import create_connection

MODULE_NAME = "smtp"
MAX_SCORE = 10.0

SOFTWARE_SIGNATURES = [
    ("postfix", "Postfix"),
    ("exim", "Exim"),
    ("sendmail", "Sendmail"),
    ("qmail", "qmail"),
    ("microsoft", "Microsoft Exchange"),
    ("exchange", "Microsoft Exchange"),
    ("exchangeonline", "Microsoft Exchange Online"),
    ("mail.edge-cs.net", "Microsoft 365"),
    ("ironport", "Cisco IronPort"),
    ("barracuda", "Barracuda"),
    ("mimecast", "Mimecast"),
    ("proofpoint", "Proofpoint"),
    ("spamassassin", "SpamAssassin"),
    ("true550", "Trend Micro"),
    ("zix", "Zix"),
    ("cfesmtp", "Cloudflare Email"),
    ("amazon", "Amazon SES"),
    ("google", "Google"),
    ("googlemail", "Google"),
    ("esmtp", "Generic ESMTP"),
]

KNOWN_SMTP_SERVERS = {
    "googleworkspace": ["smtp.google.com"],
    "microsoft365": ["mail.protection.outlook.com", "outlook.com"],
}


def _guess_software(banner: str, ehlo_host: str) -> str | None:
    combined = f"{banner} {ehlo_host}".lower()
    for pattern, name in SOFTWARE_SIGNATURES:
        if pattern in combined:
            return name
    return None


def _smtp_readline(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    data = b""
    while b"\r\n" not in data and b"\n" not in data and len(data) < 2048:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="ignore").strip()


def _probe_host(mx: MXInfo, config: ScanConfig) -> list[Finding]:
    out: list[Finding] = []
    sock = None
    try:
        sock = create_connection(mx.hostname, SMTP_PORT, config.timeout)
        banner = _smtp_readline(sock, config.timeout)
        if not banner:
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"MX {mx.hostname}: no SMTP banner received",
                    detail="The server did not send a greeting banner on port 25.",
                    recommendation="Verify the MX host serves SMTP on port 25 and is reachable.",
                    rfc_ref=RFC["SMTP"],
                )
            )
            return out

        software = _guess_software(banner, "")
        if software:
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.INFO,
                    title=f"MX {mx.hostname}: banner suggests {software}",
                    detail=f"Banner: {banner}",
                    recommendation="Banner may reveal software; consider hiding version strings.",
                    rfc_ref=RFC["SMTP"],
                )
            )

        sock.sendall(b"EHLO mailsec.local\r\n")
        ehlo_reply = _smtp_readline(sock, config.timeout)
        ehlo_multiline = [ehlo_reply]
        # Collect multi-line 250 responses
        first_code = ehlo_reply[:3] if ehlo_reply else ""
        sock.settimeout(2.0)
        try:
            while True:
                line = sock.recv(1024)
                if not line:
                    break
                ehlo_multiline.append(line.decode(errors="ignore").strip())
        except TimeoutError:
            pass

        if first_code != "250":
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title=f"MX {mx.hostname}: EHLO rejected ({first_code})",
                    detail=f"Server replied: {ehlo_reply[:200]}",
                    recommendation="The server may restrict EHLO to known senders.",
                    rfc_ref=RFC["SMTP"],
                )
            )

        caps = " ".join(ehlo_multiline).upper()
        if "STARTTLS" in caps:
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"MX {mx.hostname}: STARTTLS advertised",
                    detail="",
                    recommendation="",
                    rfc_ref=RFC["STARTTLS"],
                )
            )
        else:
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.CRITICAL,
                    title=f"MX {mx.hostname}: STARTTLS NOT advertised",
                    detail="The server does not offer STARTTLS, so transport is unencrypted "
                    "and susceptible to downgrade/eavesdropping.",
                    recommendation="Enable STARTTLS; ideally enforce it via MTA-STS or DANE.",
                    rfc_ref=RFC["STARTTLS"],
                )
            )

        if "AUTH" in caps:
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.LOW,
                    title=f"MX {mx.hostname}: AUTH capability advertised",
                    detail="AUTH is available on the public relay; ensure it is not misconfigured "
                    "for open submission.",
                    recommendation="Restrict AUTH to authenticated submission on port 587/465.",
                    rfc_ref=RFC["SMTP"],
                )
            )

        # Software detection again on full EHLO response
        software = _guess_software(first_code or "", " ".join(ehlo_multiline))
        if software:
            out.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.LOW,
                    title=f"MX {mx.hostname}: fingerprints as {software}",
                    detail="EHLO extensions reveal the mail platform to unauthenticated callers.",
                    recommendation="Reduce banner/extension verbosity where the vendor allows it.",
                    rfc_ref=RFC["SMTP"],
                )
            )

    except TimeoutError:
        out.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"MX {mx.hostname}: SMTP reachability not verified",
                detail="The connection to port 25 timed out from this scanner vantage point.",
                recommendation="Retry from an authorized network that permits outbound SMTP.",
                rfc_ref=RFC["SMTP"],
                verification_status="TOOL_INCOMPLETE",
            )
        )
    except (ConnectionRefusedError, OSError) as e:
        out.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"MX {mx.hostname}: SMTP reachability not verified",
                detail=f"Could not establish a connection from this scanner vantage point: {e}",
                recommendation="Retry from an authorized network that permits outbound SMTP before assessing the server.",
                rfc_ref=RFC["SMTP"],
                verification_status="TOOL_INCOMPLETE",
            )
        )
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return out


def run(config: ScanConfig, mx_hosts: list[MXInfo]) -> ModuleResult:
    """Run SMTP handshake probes against every MX host."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)

    if not mx_hosts:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No MX hosts to probe",
                detail="SMTP checks skipped because no MX records were resolved.",
                recommendation="",
                rfc_ref="",
            )
        )
        return result

    for mx in mx_hosts:
        result.findings.extend(_probe_host(mx, config))

    if result.findings and all(f.verification_status == "TOOL_INCOMPLETE" for f in result.findings):
        result.assessed = False

    return result
