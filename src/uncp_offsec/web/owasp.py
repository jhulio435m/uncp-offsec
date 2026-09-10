"""Honest OWASP Top 10:2025 coverage accounting."""

from __future__ import annotations

from mailsec.models import ModuleResult

OWASP_TOP_10_2025 = (
    ("A01:2025", "Broken Access Control", ("dast", "anonymous_access"), True),
    ("A02:2025", "Security Misconfiguration", ("headers", "tls", "nmap", "dast", "anonymous_access"), False),
    ("A03:2025", "Software Supply Chain Failures", ("sca", "cves"), False),
    ("A04:2025", "Cryptographic Failures", ("tls", "sast", "anonymous_access"), False),
    ("A05:2025", "Injection", ("dast", "sqli", "sast"), False),
    ("A06:2025", "Insecure Design", (), True),
    ("A07:2025", "Authentication Failures", ("dast", "anonymous_access"), True),
    ("A08:2025", "Software or Data Integrity Failures", ("sca", "sast"), True),
    ("A09:2025", "Security Logging and Alerting Failures", ("sast",), True),
    ("A10:2025", "Mishandling of Exceptional Conditions", ("dast", "sast"), True),
)


def coverage(modules: dict[str, ModuleResult], *, authenticated: bool = False) -> list[dict]:
    """Describe evidence sources and limitations without claiming full OWASP coverage."""
    rows = []
    for category_id, name, candidates, manual_required in OWASP_TOP_10_2025:
        requested = [module for module in candidates if module in modules]
        assessed = [module for module in requested if modules[module].assessed]
        if not requested:
            status = "MANUAL_REQUIRED" if manual_required else "NOT_ASSESSED"
        elif assessed:
            status = "PARTIAL"
        else:
            status = "INCOMPLETE"
        limitations = []
        if manual_required:
            limitations.append("Requires design, business-logic, authorization, or operational review.")
        if category_id in ("A01:2025", "A07:2025") and not authenticated:
            limitations.append("No authenticated test context was supplied.")
        rows.append(
            {
                "id": category_id,
                "name": name,
                "status": status,
                "evidence_modules": assessed,
                "requested_modules": requested,
                "manual_required": manual_required,
                "limitations": limitations,
            }
        )
    return rows
