from mailsec.models import Severity
from uncp_offsec.web.zap import alert_severity, parse_alerts


def test_zap_alert_retains_reproducible_evidence_and_cwe():
    alerts = [
        {
            "pluginId": "40018",
            "riskcode": "3",
            "name": "SQL Injection",
            "url": "http://lab.local/api/items?id=1",
            "method": "GET",
            "param": "id",
            "attack": "1' OR '1'='1",
            "evidence": "database error",
            "confidence": "High",
            "cweid": "89",
            "solution": "Use parameterized queries.",
        }
    ]

    findings = parse_alerts(alerts)

    assert findings[0].severity is Severity.HIGH
    assert findings[0].rfc_ref == "CWE-89"
    assert "Parameter: id" in findings[0].detail
    assert "Attack: 1' OR '1'='1" in findings[0].detail


def test_zap_deduplicates_and_ignores_false_positive():
    duplicate = {
        "pluginId": "10020",
        "riskcode": "1",
        "name": "Missing Header",
        "url": "http://lab.local/",
        "param": "",
        "attack": "",
    }
    false_positive = {**duplicate, "pluginId": "x", "confidence": "False Positive"}
    assert len(parse_alerts([duplicate, duplicate, false_positive])) == 1


def test_zap_core_api_risk_name_maps_to_severity():
    assert alert_severity({"risk": "Medium"}) is Severity.MEDIUM
    assert alert_severity({"risk": "High"}) is Severity.HIGH


def test_zap_drops_csp_claim_when_evidence_lacks_claimed_token():
    base = {
        "riskcode": "2", "confidence": "High", "evidence": "upgrade-insecure-requests",
        "url": "https://example.com/",
    }
    alerts = [
        {**base, "pluginId": "1", "name": "CSP: Wildcard Directive"},
        {**base, "pluginId": "2", "name": "CSP: script-src unsafe-inline"},
        {**base, "pluginId": "3", "name": "CSP: Failure to Define Directive with No Fallback"},
    ]

    findings = parse_alerts(alerts)

    assert [finding.title for finding in findings] == [
        "CSP: Failure to Define Directive with No Fallback"
    ]


def test_zap_limits_representative_samples_and_prefers_pages():
    alerts = [
        {
            "pluginId": "10020", "riskcode": "1", "name": "Missing Header",
            "url": f"https://example.com/static/{index}.js", "method": "GET",
        }
        for index in range(5)
    ]
    alerts.append({
        "pluginId": "10020", "riskcode": "1", "name": "Missing Header",
        "url": "https://example.com/login", "method": "GET",
    })

    finding = parse_alerts(alerts)[0]

    assert finding.occurrence_count == 6
    assert "representative samples: 3" in finding.detail
    assert "https://example.com/login" in finding.detail
    assert finding.detail.count("URL:") == 3


def test_zap_treats_xsrf_cookie_without_httponly_as_contextual():
    finding = parse_alerts([{
        "pluginId": "10010", "riskcode": "1", "name": "Cookie No HttpOnly Flag",
        "url": "https://example.com/", "param": "XSRF-TOKEN",
        "evidence": "set-cookie: XSRF-TOKEN", "confidence": "Medium",
    }])[0]

    assert finding.severity is Severity.INFO
    assert finding.verification_status == "CONTEXTUAL"
    assert "session cookies" in finding.recommendation
