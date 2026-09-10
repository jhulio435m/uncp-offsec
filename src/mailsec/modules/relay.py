"""Open-relay detection (active test). Requires --active.

The probe stops before the DATA phase, so no mail is actually delivered.
"""

from __future__ import annotations

import random
import socket

from ..constants import RFC, SMTP_PORT
from ..models import Finding, ModuleResult, MXInfo, ScanConfig, Severity
from ..network import create_connection

MODULE_NAME = "relay"
MAX_SCORE = 15.0

# Randomized test domains; never local. We want to test whether the server
# accepts relaying for non-local recipients.
_TEST_RECIPIENT_DOMAIN = "non-existent-invalid-tld.test"

_FROM = "mailsec-test@invalid.local"
_VISIT_DOMAINS = ["example.org", "example.net", "example.com"]


def _recv_line(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\r\n" not in data and b"\n" not in data and len(data) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass
    return data.decode(errors="ignore").strip()


def _probe_host(mx: MXInfo, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    sock = None
    try:
        sock = create_connection(mx.hostname, SMTP_PORT, config.timeout)
        _recv_line(sock, config.timeout)
        sock.sendall(b"EHLO mailsec.test.local\r\n")
        # drain EHLO response
        sock.settimeout(1.5)
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
        except TimeoutError:
            pass

        from_addr = f"mailsec-check@{config.domain}"
        sock.sendall(f"MAIL FROM:<{from_addr}>\r\n".encode())
        mail_reply = _recv_line(sock, config.timeout)

        if not mail_reply.startswith("250"):
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.INFO,
                    title=f"MX {mx.hostname}: MAIL FROM rejected",
                    detail=f"Server replied: {mail_reply[:160]}",
                    recommendation="Server may restrict unknown envelope senders.",
                    rfc_ref=RFC["SMTP"],
                )
            )
            return findings

        rcpt_domain = random.choice(_VISIT_DOMAINS)
        rcpt_addr = f"postmaster@{rcpt_domain}"
        sock.sendall(f"RCPT TO:<{rcpt_addr}>\r\n".encode())
        rcpt_reply = _recv_line(sock, config.timeout)

        if rcpt_reply.startswith(("250", "251")):
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.CRITICAL,
                    title=f"MX {mx.hostname}: OPEN RELAY detected",
                    detail=(f"Server accepted relaying for {rcpt_addr} without authentication. "
                            "Any host can use this server to send spam/phishing as any sender."),
                    recommendation="Disable relaying for unauthenticated senders. Permit relaying "
                    "only for authenticated users on the submission port.",
                    rfc_ref=RFC["SMTP"],
                )
            )
        elif rcpt_reply.startswith("55"):
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"MX {mx.hostname}: relay blocked ({rcpt_reply[:3]})",
                    detail=f"Server refused relay to {rcpt_addr}: {rcpt_reply[:160]}",
                    recommendation="",
                    rfc_ref="",
                )
            )
        else:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.INFO,
                    title=f"MX {mx.hostname}: relay refused",
                    detail=f"Server replied: {rcpt_reply[:160]}",
                    recommendation="",
                    rfc_ref="",
                )
            )

        # Send QUIT to close cleanly - never DATA.
        try:
            sock.sendall(b"QUIT\r\n")
            _recv_line(sock, config.timeout)
        except Exception:
            pass

    except (TimeoutError, OSError) as e:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"MX {mx.hostname}: relay probe failed",
                detail=f"{e.__class__.__name__}: {e}",
                recommendation="",
                rfc_ref="",
            )
        )
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return findings


def run(config: ScanConfig, mx_hosts: list[MXInfo]) -> ModuleResult:
    """Run controlled open-relay probes (stops before DATA)."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)

    if not config.active:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Relay test skipped",
                detail="Active testing disabled. Re-run with --active to probe open relay.",
                recommendation="",
                rfc_ref="",
            )
        )
        return result

    if not mx_hosts:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No MX hosts to probe",
                detail="Relay test skipped.",
                recommendation="",
                rfc_ref="",
            )
        )
        return result

    for mx in mx_hosts:
        result.findings.extend(_probe_host(mx, config))

    return result
