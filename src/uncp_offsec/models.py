"""Models for the unified UnCP OffSec scan (web phase + combined result)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from mailsec.models import ModuleResult


@dataclass
class HostInfo:
    """A live HTTP(S) host discovered during probing."""

    url: str
    host: str
    status: int = 0
    title: str = ""
    tech: list[str] = field(default_factory=list)
    webserver: str = ""
    scheme: str = ""
    ip: str = ""
    cdn: str = ""
    tech_versions: dict[str, str] = field(default_factory=dict)
    cves: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "status": self.status,
            "title": self.title,
            "tech": self.tech,
            "webserver": self.webserver,
            "scheme": self.scheme,
            "ip": self.ip,
            "cdn": self.cdn,
            "tech_versions": self.tech_versions,
            "cves": self.cves,
            "headers": self.headers,
        }


@dataclass
class WebScanResult:
    """Top-level result of a web asset scan."""

    domain: str
    modules: list[ModuleResult] = field(default_factory=list)
    total_score: float = 0.0
    max_score: float = 100.0
    risk_level: str = "UNKNOWN"
    coverage_score: float = 0.0
    confidence: str = "LOW"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[HostInfo] = field(default_factory=list)
    mx_hosts: list = field(default_factory=list)
    dns_records: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    owasp_coverage: list[dict[str, Any]] = field(default_factory=list)
    authenticated: bool = False
    coverage_metrics: dict[str, Any] = field(default_factory=dict)
    target_mode: str = "domain-discovery"

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "total_score": self.total_score,
            "max_score": self.max_score,
            "risk_level": self.risk_level,
            "coverage_score": self.coverage_score,
            "confidence": self.confidence,
            "subdomains": sorted(self.subdomains),
            "live_hosts": [h.to_dict() for h in self.live_hosts],
            "dns_records": self.dns_records,
            "owasp_coverage": self.owasp_coverage,
            "authenticated": self.authenticated,
            "coverage_metrics": self.coverage_metrics,
            "target_mode": self.target_mode,
            "modules": [m.to_dict() for m in self.modules],
        }


@dataclass
class CombinedScanResult:
    """Result aggregating the email (MailSec) and web phases."""

    domain: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool_version: str = "0.2.0"
    overall_score: float = 0.0
    overall_max: float = 100.0
    overall_risk: str = "UNKNOWN"
    email: Any = None
    web: Any = None
    email_modules: int = 0
    web_modules: int = 0
    scan_profile: str = "standard"
    scope_name: str = ""
    assessment_mode: str = "identification-only"
    elapsed_seconds: float = 0.0
    comparison: dict[str, list[str]] = field(default_factory=dict)
    target_mode: str = "domain-discovery"

    def _phase_dict(self, result: Any, name: str) -> dict:
        if result is None:
            return {}
        payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        breakdown = getattr(result, "breakdown", None)
        if breakdown is not None:
            payload["risk"] = breakdown.to_dict()
        payload["phase"] = name
        return payload

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "tool": "uncp_offsec",
            "tool_version": self.tool_version,
            "overall": {
                "total": round(self.overall_score, 1),
                "max": self.overall_max,
                "risk_level": self.overall_risk,
            },
            "execution": {
                "profile": self.scan_profile,
                "scope": self.scope_name or None,
                "assessment_mode": self.assessment_mode,
                "elapsed_seconds": round(self.elapsed_seconds, 3),
                "target_mode": self.target_mode,
            },
            "comparison": self.comparison,
            "email": self._phase_dict(self.email, "email"),
            "web": self._phase_dict(self.web, "web"),
        }
