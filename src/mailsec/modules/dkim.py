"""DKIM (DomainKeys Identified Mail) analysis per RFC 6376 and RFC 8301."""

from __future__ import annotations

import base64

import dns.resolver
from dns.exception import DNSException

from ..constants import (
    DKIM_BANNED_HASHES,
    DKIM_MIN_RSA_KEY_BITS,
    DKIM_RECOMMENDED_RSA_KEY_BITS,
    RFC,
)
from ..models import Finding, ModuleResult, ScanConfig, Severity

MODULE_NAME = "dkim"
MAX_SCORE = 12.0


def _decode_dns_txt(answers) -> str:
    for r in answers:
        if r.rdtype == 16:  # TXT
            parts = [s.decode(errors="ignore") for s in r.strings]
            if parts:
                return "".join(parts)
    return ""


def _parse_key_record(record: str) -> dict:
    """Parse a DKIM public key TXT record into its tag=value pairs."""
    parsed = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            parsed[key.strip()] = value.strip()
    return parsed


def _estimate_rsa_key_bits(pem: str) -> int | None:
    """Best-effort RSA modulus size estimate from a raw DER base64 SPKI key."""
    try:
        der = base64.b64decode(pem.replace("\n", ""))
        # Find the modulus: it is the second INTEGER in the DER sequence.
        # We look for the largest contiguous chunk of bytes as a heuristic.
        # Simpler: search for the SEQUENCE length prefix pattern.
        if der and der[0] == 0x30:
            # Attempt: parse first two INTEGERs
            pos = 2
            if pos < len(der) and der[pos] == 0x02:
                # first integer (algorithm oid, 9-11 bytes typically)
                pass
        # Heuristic: the modulus length correlates with the key size.
        # Instead, decode via cryptography if available.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        spki = serialization.load_der_public_key(der)
        if isinstance(spki, rsa.RSAPublicKey):
            return spki.key_size
    except Exception:
        return None
    return None


def run(config: ScanConfig) -> ModuleResult:
    """Probe common DKIM selectors and analyze found key records."""
    result = ModuleResult(name=MODULE_NAME, score_contribution=0.0, max_score=MAX_SCORE)

    selectors: dict[str, dict] = {}
    found_any = False

    for selector in config.dkim_selectors:
        fqdn = f"{selector}._domainkey.{config.domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "TXT", lifetime=config.timeout)
        except DNSException:
            continue

        record = _decode_dns_txt(answers)
        if not record:
            continue
        found_any = True
        selectors[selector] = _parse_key_record(record)

    if not found_any:
        result.findings.append(
            Finding(
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="No DKIM key found for common selectors",
                detail="None of the common selectors resolved to a DKIM public key. "
                "The organization may not sign outbound mail, or uses a non-standard selector.",
                recommendation="Publish DKIM keys and sign outbound mail, or identify the custom selector.",
                rfc_ref=RFC["DKIM"],
            )
        )
        return result

    result.findings.append(
        Finding(
            module=MODULE_NAME,
            severity=Severity.INFO,
            title=f"DKIM key(s) found: {', '.join(sorted(selectors))}",
            detail="Selectors discovered and analyzed.",
            recommendation="Ensure all selectors correspond to actively used signing infrastructure.",
            rfc_ref=RFC["DKIM"],
        )
    )

    for selector, parsed in selectors.items():
        v = parsed.get("v", "DKIM1")
        h = parsed.get("h", "").lower()
        k = parsed.get("k", "rsa").lower()
        p = parsed.get("p", "")
        s = parsed.get("s", "").lower()

        if v != "DKIM1":
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title=f"DKIM selector {selector}: unexpected v={v}",
                    detail="The DKIM version tag is not DKIM1.",
                    recommendation="Correct the v= tag to DKIM1.",
                    rfc_ref=RFC["DKIM"],
                )
            )

        if k not in ("rsa", "ed25519"):
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.LOW,
                    title=f"DKIM selector {selector}: unknown key type {k}",
                    detail="Key type is not rsa or ed25519.",
                    recommendation="Use an RSA or Ed25519 key.",
                    rfc_ref=RFC["DKIM"],
                )
            )

        if not p:
            result.findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=Severity.HIGH,
                    title=f"DKIM selector {selector}: empty public key (p=)",
                    detail="The published key has no p= value; signatures cannot be verified.",
                    recommendation="Publish the full base64 public key.",
                    rfc_ref=RFC["DKIM"],
                )
            )
        else:
            if k == "rsa":
                bits = _estimate_rsa_key_bits(p)
                if bits is None:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.INFO,
                            title=f"DKIM selector {selector}: key size unavailable from record",
                            detail="Public key parsed but size could not be estimated from the TXT record alone.",
                            recommendation="",
                            rfc_ref="",
                        )
                    )
                elif bits < DKIM_MIN_RSA_KEY_BITS:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.CRITICAL,
                            title=f"DKIM selector {selector}: RSA key too small ({bits} bits)",
                            detail=f"RSA keys below {DKIM_MIN_RSA_KEY_BITS} bits violate RFC 8301.",
                            recommendation=f"Rotate to a key of at least {DKIM_RECOMMENDED_RSA_KEY_BITS} bits.",
                            rfc_ref=RFC["DKIM_KEY"],
                        )
                    )
                elif bits < DKIM_RECOMMENDED_RSA_KEY_BITS:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.LOW,
                            title=f"DKIM selector {selector}: RSA key {bits} bits (below recommended)",
                            detail=f"Key meets the {DKIM_MIN_RSA_KEY_BITS}-bit minimum but is below the "
                            f"recommended {DKIM_RECOMMENDED_RSA_KEY_BITS} bits.",
                            recommendation="Rotate to a 2048-bit key for future-proofing.",
                            rfc_ref=RFC["DKIM_KEY"],
                        )
                    )
                else:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.PASS,
                            title=f"DKIM selector {selector}: strong RSA key ({bits} bits)",
                            detail="",
                            recommendation="",
                            rfc_ref="",
                        )
                    )

            if h:
                hashes = [x.strip() for x in h.split(":") if x.strip()]
                weak = [x for x in hashes if x in DKIM_BANNED_HASHES]
                if weak:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.CRITICAL,
                            title=f"DKIM selector {selector}: weak hash algorithm: {', '.join(weak)}",
                            detail="rsa-sha1 is prohibited by RFC 8301.",
                            recommendation="Rotate to rsa-sha256 only.",
                            rfc_ref=RFC["DKIM_KEY"],
                        )
                    )
                elif "sha256" in hashes:
                    result.findings.append(
                        Finding(
                            module=MODULE_NAME,
                            severity=Severity.PASS,
                            title=f"DKIM selector {selector}: sha256 hash in use",
                            detail="",
                            recommendation="",
                            rfc_ref="",
                        )
                    )

            if s:
                # s= tags service types; not strictly a vuln, but log it
                result.findings.append(
                    Finding(
                        module=MODULE_NAME,
                        severity=Severity.INFO,
                        title=f"DKIM selector {selector}: service types s={s}",
                        detail="The s= tag restricts usage to the listed service types.",
                        recommendation="",
                        rfc_ref="",
                    )
                )

    return result
