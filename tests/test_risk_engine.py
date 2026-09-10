"""Tests for the risk scoring engine."""

from __future__ import annotations

from mailsec.models import Finding, ModuleResult, Severity
from mailsec.scoring.risk_engine import _risk_level, compute_score


def _mk(sev: Severity, title: str = "x") -> ModuleResult:
    return ModuleResult(name="x", findings=[Finding(module="x", severity=sev, title=title)])


def _worst(sev: Severity) -> ModuleResult:
    return _mk(sev)


def test_good_configuration_scores_high():
    mods = {
        "spf": _worst(Severity.PASS),
        "dkim": _worst(Severity.PASS),
        "smtp": _worst(Severity.PASS),
        "starttls": _worst(Severity.PASS),
        "mta_sts": _worst(Severity.PASS),
        "dane": _worst(Severity.MEDIUM),
        "tls_rpt": _worst(Severity.PASS),
        "relay": _worst(Severity.PASS),
    }
    policy = {"p": "reject", "sp": "reject", "pct": "100", "rua": "mailto:x"}
    r = compute_score(mods, policy)
    assert r.risk_level in ("GOOD", "LOW")
    assert r.total >= 90


def test_bad_configuration_scores_low():
    mods = {
        "spf": _worst(Severity.CRITICAL),
        "dkim": _worst(Severity.MEDIUM),
        "smtp": _worst(Severity.CRITICAL),
        "starttls": _worst(Severity.MEDIUM),
        "mta_sts": _worst(Severity.MEDIUM),
        "dane": _worst(Severity.MEDIUM),
        "tls_rpt": _worst(Severity.LOW),
        "relay": _worst(Severity.CRITICAL),
    }
    policy = {"p": "none", "pct": "50"}
    r = compute_score(mods, policy)
    assert r.risk_level == "CRITICAL"
    assert r.total < 40


def test_dmarc_none_reduces_antispoofing():
    mods = {k: _worst(Severity.PASS) for k in
            ("spf", "dkim", "smtp", "starttls", "mta_sts", "dane", "tls_rpt", "relay")}
    r_none = compute_score(dict(mods), {"p": "none"})
    r_reject = compute_score(dict(mods), {"p": "reject", "pct": "100"})

    anti_none = [c for c in r_none.categories if c.name == "Anti-Spoofing"][0].score
    anti_reject = [c for c in r_reject.categories if c.name == "Anti-Spoofing"][0].score
    assert anti_reject > anti_none


def test_missing_dmarc_hurts_score():
    mods = {k: _worst(Severity.PASS) for k in
            ("spf", "dkim", "smtp", "starttls", "mta_sts", "dane", "tls_rpt", "relay")}
    r = compute_score(mods, {})
    assert r.total < 80  # anti-spoofing collapses without DMARC


def test_risk_thresholds():
    assert compute_score({}, {}).risk_level == "CRITICAL"
    assert _risk_level(35.5) == "CRITICAL"
    assert _risk_level(55.5) == "HIGH"
    assert _risk_level(75.5) == "MEDIUM"
    assert _risk_level(90.5) == "LOW"
