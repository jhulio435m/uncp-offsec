"""Core data models for MailSec Auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""

    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> float:
        """Numeric weight used by the scoring engine."""
        return {
            Severity.PASS: 1.0,
            Severity.INFO: 0.9,
            Severity.LOW: 0.7,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.25,
            Severity.CRITICAL: 0.0,
        }[self]


@dataclass
class Finding:
    """A single finding produced by a module."""

    module: str
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""
    rfc_ref: str = ""
    confidence: str = "UNSPECIFIED"
    verification_status: str = "OBSERVED"
    occurrence_count: int = 1
    owasp_categories: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "rfc_ref": self.rfc_ref,
            "confidence": self.confidence,
            "verification_status": self.verification_status,
            "occurrence_count": self.occurrence_count,
            "owasp_categories": self.owasp_categories,
            "cve_ids": self.cve_ids,
        }


@dataclass
class ModuleResult:
    """Aggregated output from a single scan module."""

    name: str
    findings: list[Finding] = field(default_factory=list)
    score_contribution: float = 0.0
    max_score: float = 0.0
    assessed: bool = True

    @property
    def status(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        worst = max((f.severity for f in self.findings), key=lambda s: s.weight * -1)
        return worst

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "assessed": self.assessed,
            "score_contribution": self.score_contribution,
            "max_score": self.max_score,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class MXInfo:
    """DNS MX record metadata."""

    hostname: str
    preference: int

    @property
    def provider(self) -> str:
        """Best-effort provider detection from hostname."""
        h = self.hostname.lower()
        if "google" in h or "googlegroups" in h:
            return "Google Workspace"
        if "outlook" in h or "office365" in h or "protection" in h:
            return "Microsoft 365"
        if "mimecast" in h:
            return "Mimecast"
        if "proofpoint" in h:
            return "Proofpoint"
        if "amazonses" in h or "amazonaws" in h:
            return "Amazon SES"
        if "cloudflare" in h:
            return "Cloudflare"
        if "zoho" in h:
            return "Zoho"
        if "protonmail" in h or "proton" in h:
            return "ProtonMail"
        if "mailgun" in h:
            return "Mailgun"
        if "sendgrid" in h or "sg" in h:
            return "SendGrid"
        return "Custom/Unknown"

    def to_dict(self) -> dict:
        return {"hostname": self.hostname, "preference": self.preference}


@dataclass
class ScanConfig:
    """Runtime configuration for a scan."""

    domain: str
    active: bool = False
    timeout: float = 10.0
    tls_timeout: float = 15.0
    dkim_selectors: list[str] = field(
        default_factory=lambda: [
            "default",
            "mail",
            "google",
            "selector1",
            "selector2",
            "selector3",
            "k1",
            "k2",
            "s1",
            "s2",
            "mailchimp",
            "sor2026",
            "dkim",
            "zoho",
        ]
    )
    verify_cert: bool = True
    max_threads: int = 8


@dataclass
class ScanResult:
    """Top-level result of an entire scan."""

    domain: str
    modules: list[ModuleResult] = field(default_factory=list)
    total_score: float = 0.0
    max_score: float = 100.0
    risk_level: str = "UNKNOWN"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    mx_hosts: list[MXInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "total_score": self.total_score,
            "max_score": self.max_score,
            "risk_level": self.risk_level,
            "mx_hosts": [m.to_dict() for m in self.mx_hosts],
            "modules": [m.to_dict() for m in self.modules],
        }
