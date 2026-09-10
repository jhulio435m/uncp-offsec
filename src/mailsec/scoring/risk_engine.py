"""Risk scoring engine: maps module findings to weighted category scores."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..constants import RISK_THRESHOLDS
from ..models import ModuleResult, Severity

# Per-category module maxima
DOMAIN_AUTH_MAX = 40.0
SMTP_TRANSPORT_MAX = 25.0
ANTI_SPOOFING_MAX = 20.0
INFRA_EXPOSURE_MAX = 10.0
MONITORING_MAX = 5.0
TOTAL_MAX = 100.0

SPF_WEIGHT = 18.0
DKIM_WEIGHT = 12.0
DMARC_WEIGHT = 10.0

STARTTLS_WEIGHT = 12.0
MTA_STS_WEIGHT = 10.0
DANE_WEIGHT = 3.0

# Severity -> scoring weight
_SEV_W = {
    Severity.PASS: 1.0,
    Severity.INFO: 0.9,
    Severity.LOW: 0.75,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.25,
    Severity.CRITICAL: 0.0,
}


@dataclass
class CategoryScore:
    name: str
    score: float = 0.0
    max: float = 0.0
    label: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "score": round(self.score, 1), "max": self.max}


@dataclass
class RiskBreakdown:
    categories: list[CategoryScore] = field(default_factory=list)
    total: float = 0.0
    risk_level: str = "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "total": round(self.total, 1),
            "max": TOTAL_MAX,
            "risk_level": self.risk_level,
            "categories": [c.to_dict() for c in self.categories],
        }


def _worst(module: ModuleResult | None) -> Severity | None:
    """Worst finding severity, ignoring skips/notices."""
    if module is None or not module.findings:
        return None
    relevant = []
    for f in module.findings:
        title = f.title.lower()
        if "no mx hosts to probe" in title or "skipped" in title and f.severity == Severity.INFO:
            continue
        relevant.append(f)
    issues = [
        f for f in relevant
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    if issues:
        return min(issues, key=lambda f: _SEV_W[f.severity]).severity
    if any(f.severity == Severity.PASS for f in relevant):
        return Severity.PASS
    return Severity.INFO


def _sev_score(module: ModuleResult, weight: float) -> float:
    sev = _worst(module)
    if sev is None:
        return 0.0
    return round(weight * _SEV_W[sev], 1)


def _has_pass(module: ModuleResult | None, title_fragment: str = "") -> bool:
    if module is None:
        return False
    for f in module.findings:
        if f.severity == Severity.PASS and title_fragment.lower() in f.title.lower():
            return True
    return False


def _risk_level(total: float) -> str:
    for lo, hi, label in RISK_THRESHOLDS:
        if lo <= total <= hi:
            return label
    return "UNKNOWN"


def compute_score(
    modules: dict[str, ModuleResult],
    dmarc_policy: dict | None = None,
) -> RiskBreakdown:
    """Compute category + total scores from a scan's module results."""
    dmarc_policy = dmarc_policy or {}
    categories: list[CategoryScore] = []

    # ---- Domain Authentication (40) ----
    spf_score = _sev_score(modules.get("spf"), SPF_WEIGHT)
    dkim_score = _sev_score(modules.get("dkim"), DKIM_WEIGHT)

    dmarc_score = DMARC_WEIGHT
    p = dmarc_policy.get("p", "").lower()
    if not p:
        dmarc_score = 0.0
    elif p == "reject":
        dmarc_score = DMARC_WEIGHT
    elif p == "quarantine":
        dmarc_score = 7.0
    else:  # none
        dmarc_score = 4.0
    try:
        pct = int(dmarc_policy.get("pct", "100"))
    except (TypeError, ValueError):
        pct = 100
    if pct < 100:
        dmarc_score -= 2.0
    sp = dmarc_policy.get("sp", "").lower()
    if p and sp == "none":
        dmarc_score -= 1.0
    dmarc_score = max(0.0, min(DMARC_WEIGHT, dmarc_score))

    domain_auth = CategoryScore(
        name="Domain Authentication",
        score=round(spf_score + dkim_score + dmarc_score, 1),
        max=DOMAIN_AUTH_MAX,
        label="SPF/DKIM/DMARC policy",
    )
    categories.append(domain_auth)

    # ---- SMTP Transport (25) ----
    starttls_score = _sev_score(modules.get("starttls"), STARTTLS_WEIGHT)
    mta_sts_score = _sev_score(modules.get("mta_sts"), MTA_STS_WEIGHT)
    dane_score = _sev_score(modules.get("dane"), DANE_WEIGHT)

    smtp_transport = CategoryScore(
        name="SMTP Transport",
        score=round(starttls_score + mta_sts_score + dane_score, 1),
        max=SMTP_TRANSPORT_MAX,
        label="STARTTLS/MTA-STS/DANE",
    )
    categories.append(smtp_transport)

    # ---- Anti-Spoofing (20) ----
    anti_spoofing = ANTI_SPOOFING_MAX
    if not p:
        anti_spoofing = 0.0
    else:
        if p == "none":
            anti_spoofing = 5.0
        elif p == "quarantine":
            anti_spoofing = 12.0
        else:  # reject
            anti_spoofing = 16.0
        if sp in ("reject", "quarantine"):
            anti_spoofing += 2.0
        if pct == 100:
            anti_spoofing += 1.0
        if dmarc_policy.get("adkim", "r").lower() == "s":
            anti_spoofing += 0.5
        if dmarc_policy.get("aspf", "r").lower() == "s":
            anti_spoofing += 0.5
    anti_spoofing = max(0.0, min(ANTI_SPOOFING_MAX, anti_spoofing))
    categories.append(
        CategoryScore(
            name="Anti-Spoofing",
            score=round(anti_spoofing, 1),
            max=ANTI_SPOOFING_MAX,
            label="DMARC enforcement + alignment",
        )
    )

    # ---- Infrastructure Exposure (10) ----
    smtp_mod = modules.get("smtp")
    leak_score = 0.0
    if smtp_mod:
        sev = _worst(smtp_mod)
        if sev is None:
            leak_score = 4.0
        elif sev == Severity.PASS or sev == Severity.INFO:
            leak_score = 6.0
        else:
            leak_score = 6.0 * _SEV_W.get(sev, 0.5)

    relay_mod = modules.get("relay")
    relay_score = 4.0
    if relay_mod:
        if _has_pass(relay_mod, "relay blocked"):
            relay_score = 4.0
        elif any(f.severity == Severity.CRITICAL and "open relay" in f.title.lower() for f in relay_mod.findings):
            relay_score = 0.0
        elif any("skipped" in f.title.lower() for f in relay_mod.findings):
            relay_score = 3.0
        else:
            relay_score = 2.0

    infra = CategoryScore(
        name="Infrastructure Exposure",
        score=round(leak_score + relay_score, 1),
        max=INFRA_EXPOSURE_MAX,
        label="banner/software disclosure + relay",
    )
    categories.append(infra)

    # ---- Monitoring (5) ----
    monitoring = 0.0
    if dmarc_policy.get("rua"):
        monitoring += 2.0
    if dmarc_policy.get("ruf"):
        monitoring += 1.0
    tls_rpt_mod = modules.get("tls_rpt")
    if tls_rpt_mod and _has_pass(tls_rpt_mod, "reporting destination"):
        monitoring += 2.0
    monitoring = max(0.0, min(MONITORING_MAX, monitoring))
    categories.append(
        CategoryScore(
            name="Monitoring",
            score=round(monitoring, 1),
            max=MONITORING_MAX,
            label="DMARC reports + TLS-RPT",
        )
    )

    total = round(sum(c.score for c in categories), 1)
    categories.append(
        CategoryScore(name="TOTAL", score=total, max=TOTAL_MAX, label="")
    )

    return RiskBreakdown(
        categories=categories,
        total=total,
        risk_level=_risk_level(total),
    )