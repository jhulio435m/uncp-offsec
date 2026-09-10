"""TLS analysis of SMTP STARTTLS connections: cert, trust chain, protocol, cipher."""

from __future__ import annotations

import datetime
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

from ..constants import RFC, SMTP_PORT
from ..models import Finding, ModuleResult, MXInfo, ScanConfig, Severity
from ..network import create_connection

MODULE_NAME = "starttls"
MAX_SCORE = 12.0

GOOD_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}
WEAK_CIPHERS = ("RC4", "3DES", "CBC", "NULL", "EXPORT", "DES")


def _to_utc(dt: datetime.datetime) -> datetime.datetime:
    """Normalize a possibly-naive datetime to UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _classify_protocol(version) -> str:
    """Map the negotiated protocol enum/value to a readable name."""
    if version is None:
        return "unknown"
    name = str(version)
    mapping = {
        "TLSv1": "TLSv1.0",
        "TLSv1.0": "TLSv1.0",
        "TLSv1.1": "TLSv1.1",
        "TLSv1.2": "TLSv1.2",
        "TLSv1.3": "TLSv1.3",
        "SSLv3": "SSLv3",
        "SSLv2": "SSLv2",
    }
    return mapping.get(name, name)


def _hostname_matches(san_names: set[str], hostname: str) -> bool:
    """RFC 6125 hostname matching, including single-label wildcard support."""
    host = hostname.lower().rstrip(".")
    for san in san_names:
        san = san.lower()
        if san == host:
            return True
        if san.startswith("*."):
            base = san[2:]
            # wildcard covers exactly one label: X.base
            if host.endswith("." + base):
                head = host[: -(len(base) + 1)]
                if head and "." not in head:
                    return True
    return False


def _analyze_cert(cert: x509.Certificate) -> list[Finding]:
    findings: list[Finding] = []

    # Validity
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or _to_utc(cert.not_valid_after)
    not_before = getattr(cert, "not_valid_before_utc", None) or _to_utc(cert.not_valid_before)
    if now > not_after:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="Certificate has expired",
                detail=f"Expired on {not_after.isoformat()}.",
                recommendation="Renew the certificate immediately.",
                rfc_ref=RFC["STARTTLS"],
            )
        )
    elif not_after - now < datetime.timedelta(days=30):
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Certificate expires within 30 days",
                detail=f"Expires on {not_after.isoformat()}.",
                recommendation="Renew before expiry to avoid transport failures.",
                rfc_ref=RFC["STARTTLS"],
            )
        )

    if now < not_before:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="Certificate not yet valid",
                detail=f"Not valid before {not_before.isoformat()}.",
                recommendation="Check server and signer clocks.",
                rfc_ref=RFC["STARTTLS"],
            )
        )

    # Public key strength
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"RSA key below 2048 bits ({pub.key_size} bits)",
                    detail="1024-bit (or weaker) RSA is deprecated.",
                    recommendation="Rotate to a 2048-bit (or larger) RSA key.",
                    rfc_ref=RFC["STARTTLS"],
                )
            )
        else:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"CERT: strong RSA key ({pub.key_size} bits)",
                    detail="",
                    recommendation="",
                    rfc_ref="",
                )
            )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        try:
            size = pub.curve.key_size
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"CERT: ECDSA curve {size}-bit",
                    detail="",
                    recommendation="",
                    rfc_ref="",
                )
            )
        except Exception:
            pass

    # Signatures
    sig_algo = cert.signature_hash_algorithm
    if isinstance(sig_algo, (hashes.SHA1, hashes.MD5)):
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.CRITICAL,
                title="Certificate signed with weak hash (SHA1/MD5)",
                detail=f"Signature algorithm: {cert.signature_algorithm_oid}",
                recommendation="Reissue the certificate with a SHA-256 signature.",
                rfc_ref=RFC["STARTTLS"],
            )
        )

    return findings


def _probe_host(
    mx: MXInfo,
    config: ScanConfig,
    banner_expected: bool = True,
) -> list[Finding]:
    """Probe STARTTLS on a single MX host. Returns findings."""
    findings: list[Finding] = []

    def _readline(sock, timeout) -> str:
        sock.settimeout(timeout)
        data = b""
        while b"\r\n" not in data and b"\n" not in data and len(data) < 2048:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
        return data.decode(errors="ignore").strip()

    raw_sock = None
    try:
        raw_sock = create_connection(mx.hostname, SMTP_PORT, config.timeout)
        if banner_expected:
            _readline(raw_sock, config.timeout)
        raw_sock.sendall(b"EHLO mailsec.local\r\n")
        _readline(raw_sock, config.timeout)
        raw_sock.settimeout(2.0)
        try:
            while True:
                chunk = raw_sock.recv(1024)
                if not chunk:
                    break
        except TimeoutError:
            pass
        raw_sock.sendall(b"STARTTLS\r\n")
        starttls_reply = _readline(raw_sock, config.timeout)
        if not starttls_reply.startswith("220"):
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.CRITICAL,
                    title=f"MX {mx.hostname}: STARTTLS rejected by server",
                    detail=f"Server replied: {starttls_reply[:200]}",
                    recommendation="SMTP sits unencrypted; fix STARTTLS handling.",
                    rfc_ref=RFC["STARTTLS"],
                )
            )
            return findings

        ctx = ssl.create_default_context()
        ctx.check_hostname = config.verify_cert
        ctx.verify_mode = ssl.CERT_REQUIRED if config.verify_cert else ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=mx.hostname)
        raw_sock = None  # ownership moved

        version = _classify_protocol(tls_sock.version())
        cipher = tls_sock.cipher()
        cipher_name = cipher[0] if cipher else "unknown"

        if version in GOOD_TLS_VERSIONS:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"MX {mx.hostname}: {version} in use",
                    detail=f"Cipher: {cipher_name}",
                    recommendation="",
                    rfc_ref="",
                )
            )
        else:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"MX {mx.hostname}: weak TLS version negotiated ({version})",
                    detail=f"Cipher: {cipher_name}",
                    recommendation="Upgrade to TLSv1.2 or TLSv1.3.",
                    rfc_ref=RFC["STARTTLS"],
                )
            )

        if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"MX {mx.hostname}: weak cipher negotiated ({cipher_name})",
                    detail="",
                    recommendation="Disable weak ciphers; prefer AEAD suites (AES-GCM/ChaCha20).",
                    rfc_ref=RFC["STARTTLS"],
                )
            )

        cert_der = tls_sock.getpeercert(binary_form=True)
        tls_sock.close()

        if cert_der is None:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"MX {mx.hostname}: no certificate returned",
                    detail="",
                    recommendation="Server must present a valid SMTP certificate.",
                    rfc_ref=RFC["STARTTLS"],
                )
            )
            return findings

        cert = x509.load_der_x509_certificate(cert_der)
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = "unknown"
        san_names = set()
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_names.add(name.value)
        except Exception:
            pass

        # When verification is enabled, the TLS handshake already validated the
        # hostname and trust chain (RFC 6125 wildcards included). The manual check
        # is only meaningful for the --no-verify-cert path.
        if config.verify_cert:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"MX {mx.hostname}: certificate chain and hostname verified",
                    detail=f"SAN covers {mx.hostname}.",
                    recommendation="",
                    rfc_ref="",
                )
            )
        elif _hostname_matches(san_names, mx.hostname) or cn == mx.hostname:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.PASS,
                    title=f"MX {mx.hostname}: certificate matches hostname",
                    detail=f"CN/SubjectAltName includes {mx.hostname}.",
                    recommendation="",
                    rfc_ref="",
                )
            )
        else:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"MX {mx.hostname}: certificate hostname mismatch",
                    detail=f"CN={cn}; SANs={sorted(san_names) or 'none'}",
                    recommendation="Present a cert that includes the MX hostname in SAN.",
                    rfc_ref=RFC["STARTTLS"],
                )
            )

        findings.extend(_analyze_cert(cert))

    except ssl.SSLCertVerificationError as e:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title=f"MX {mx.hostname}: certificate verification failed",
                detail=f"{e}",
                recommendation="Fix the trust chain or hostname mismatch.",
                rfc_ref=RFC["STARTTLS"],
            )
        )
    except ssl.SSLError as e:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title=f"MX {mx.hostname}: TLS handshake failed",
                detail=f"SSL error: {e}",
                recommendation="Check server TLS configuration.",
                rfc_ref=RFC["STARTTLS"],
            )
        )
    except TimeoutError:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"MX {mx.hostname}: STARTTLS reachability not verified",
                detail="The connection timed out from this scanner vantage point.",
                recommendation="Retry from an authorized network that permits outbound SMTP.",
                rfc_ref=RFC["STARTTLS"],
                verification_status="TOOL_INCOMPLETE",
            )
        )
    except OSError as e:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title=f"MX {mx.hostname}: STARTTLS reachability not verified",
                detail=f"Connection error from this scanner vantage point: {e}",
                recommendation="Retry from an authorized network that permits outbound SMTP.",
                rfc_ref=RFC["STARTTLS"],
                verification_status="TOOL_INCOMPLETE",
            )
        )
    finally:
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    return findings


def run(config: ScanConfig, mx_hosts: list[MXInfo]) -> ModuleResult:
    """Run STARTTLS probes against all MX hosts."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)
    if not mx_hosts:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="No MX hosts to probe",
                detail="STARTTLS checks skipped.",
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
