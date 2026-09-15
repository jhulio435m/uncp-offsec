import json

import pytest

from mailsec.models import Finding, ModuleResult, Severity
from uncp_offsec.web.auth import load_headers
from uncp_offsec.web.owasp import coverage
from uncp_offsec.web.zap import parse_alerts


def test_auth_headers_reject_host_and_newlines(tmp_path):
    path = tmp_path / "headers.json"
    path.write_text(json.dumps({"Host": "outside.example"}))
    with pytest.raises(ValueError, match="not allowed"):
        load_headers(path)
    path.write_text(json.dumps({"Authorization": "Bearer x\nInjected: yes"}))
    with pytest.raises(ValueError, match="single-line"):
        load_headers(path)


def test_owasp_coverage_never_claims_complete():
    modules = {
        "dast": ModuleResult("dast", [Finding("dast", Severity.PASS, "done")]),
        "sast": ModuleResult("sast", [Finding("sast", Severity.PASS, "done")]),
    }
    rows = coverage(modules, authenticated=True)
    assert len(rows) == 10
    assert all(row["status"] != "COMPLETE" for row in rows)
    assert next(row for row in rows if row["id"] == "A06:2025")["status"] == "MANUAL_REQUIRED"
    assert "threat models" in next(
        row for row in rows if row["id"] == "A06:2025"
    )["next_step"]


def test_zap_groups_instances_and_marks_weak_high_as_potential():
    base = {
        "pluginId": "40018", "riskcode": "3", "name": "SQL Injection",
        "confidence": "Low", "cweid": "89", "method": "GET", "param": "q",
        "evidence": "HTTP 500",
    }
    findings = parse_alerts([
        {**base, "url": "http://lab/search?q=one", "attack": "'("},
        {**base, "url": "http://lab/search?q=two", "attack": "')"},
    ])
    assert len(findings) == 1
    assert findings[0].occurrence_count == 2
    assert findings[0].verification_status == "POTENTIAL"
    assert findings[0].confidence == "LOW"
