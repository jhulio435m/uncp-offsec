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
