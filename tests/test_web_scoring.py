from mailsec.models import Finding, ModuleResult, Severity
from uncp_offsec.web.scoring import _worst, compute_coverage, compute_web_score


def _module(name: str, *severities: Severity, assessed: bool = True) -> ModuleResult:
    return ModuleResult(
        name=name,
        assessed=assessed,
        findings=[Finding(name, severity, severity.value) for severity in severities],
    )


def test_web_worst_selects_critical_over_info():
    module = _module("dast", Severity.INFO, Severity.CRITICAL, Severity.PASS)
    assert _worst(module) is Severity.CRITICAL


def test_high_finding_reduces_web_score():
    good = compute_web_score({"dast": _module("dast", Severity.PASS)})
    bad = compute_web_score({"dast": _module("dast", Severity.INFO, Severity.HIGH)})
    assert bad.total < good.total


def test_coverage_counts_unassessed_requested_modules():
    modules = {
        "dast": _module("dast", Severity.INFO, assessed=False),
        "sqli": _module("sqli", Severity.PASS),
    }
    assert compute_coverage(modules) == 37.5


def test_unassessed_module_is_not_rewarded_as_secure():
    result = compute_web_score({"dast": _module("dast", Severity.INFO, assessed=False)})
    assert result.total == 0.0
    assert result.risk_level == "CRITICAL"
