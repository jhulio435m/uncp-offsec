"""Web risk scoring: normalizes module results to a 0-100 web score.

Only modules that were actually assessed (tool present + targets existed)
count toward the total. This makes a passive-recon score comparable to an
active one without rewarding "not checked" as "secure".
"""

from __future__ import annotations

from mailsec.constants import RISK_THRESHOLDS
from mailsec.models import ModuleResult, Severity
from mailsec.scoring.risk_engine import CategoryScore, RiskBreakdown

# Module -> (weight, category)
MODULE_WEIGHTS: dict[str, tuple[float, str]] = {
    "subdomains": (4.0, "Attack Surface"),
    "live_hosts": (4.0, "Attack Surface"),
    "dns_inventory": (4.0, "Attack Surface"),
    "ports": (6.0, "Attack Surface"),
    "nmap": (8.0, "Attack Surface"),
    "tls": (8.0, "Transport Security"),
    "technology": (4.0, "Platform Hygiene"),
    "headers": (6.0, "Platform Hygiene"),
    "cves": (6.0, "Platform Hygiene"),
    "crawl": (8.0, "Application Security"),
    "content_discovery": (6.0, "Application Security"),
    "sqli": (12.0, "Application Security"),
    "vulns": (12.0, "Application Security"),
    "dast": (20.0, "Application Security"),
    "sast": (12.0, "Application Security"),
    "sca": (8.0, "Platform Hygiene"),
    "anonymous_access": (10.0, "Application Security"),
}

CATEGORY_ORDER = [
    "Attack Surface",
    "Transport Security",
    "Platform Hygiene",
    "Application Security",
]

_SEV_W = {
    Severity.PASS: 1.0,
    Severity.INFO: 0.9,
    Severity.LOW: 0.75,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.25,
    Severity.CRITICAL: 0.0,
}


def _worst(module: ModuleResult | None) -> Severity | None:
    if module is None or not module.findings:
        return None
    return min((f.severity for f in module.findings), key=lambda s: _SEV_W[s], default=None)


def compute_coverage(modules: dict[str, ModuleResult]) -> float:
    """Return weighted completion for requested security modules."""
    requested = sum(MODULE_WEIGHTS.get(name, (0.0, ""))[0] for name in modules)
    assessed = sum(
        MODULE_WEIGHTS.get(name, (0.0, ""))[0]
        for name, module in modules.items()
        if module.assessed
    )
    return round(assessed / requested * 100.0, 1) if requested else 0.0


def _risk_level(total: float) -> str:
    for lo, hi, label in RISK_THRESHOLDS:
        if lo <= total <= hi:
            return label
    return "UNKNOWN"


def compute_web_score(modules: dict[str, ModuleResult]) -> RiskBreakdown:
    """Compute the web score from assessed module results."""
    earned: dict[str, float] = {c: 0.0 for c in CATEGORY_ORDER}
    available: dict[str, float] = {c: 0.0 for c in CATEGORY_ORDER}

    for name, mr in modules.items():
        weight, category = MODULE_WEIGHTS.get(name, (0.0, ""))
        if not category or not weight:
            continue
        available[category] += weight
        sev = _worst(mr)
        assessed = mr.assessed
        factor = _SEV_W.get(sev, 1.0) if sev is not None else 1.0
        if not assessed and sev in (None, Severity.PASS, Severity.INFO):
            factor = 0.0
        earned[category] += weight * factor

    total_available = sum(available.values())
    total_earned = sum(earned.values())
    total = round(total_earned / total_available * 100.0, 1) if total_available else 0.0

    categories = [
        CategoryScore(
            name=category,
            score=round(earned[category], 1),
            max=round(available[category], 1),
        )
        for category in CATEGORY_ORDER
        if available.get(category, 0.0) > 0
    ]
    categories.append(CategoryScore(name="TOTAL", score=total, max=100.0, label=""))
    return RiskBreakdown(categories=categories, total=total, risk_level=_risk_level(total))
