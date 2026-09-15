from uncp_offsec.reports.html import render


def test_combined_html_includes_informational_evidence():
    payload = {
        "domain": "lab.local",
        "timestamp": "2026-09-09T00:00:00+00:00",
        "overall": {"total": 100, "max": 100, "risk_level": "GOOD"},
        "execution": {"assessment_mode": "identification-only"},
        "email": {},
        "web": {
            "total_score": 100,
            "modules": [
                {
                    "name": "nmap",
                    "findings": [
                        {
                            "severity": "INFO",
                            "title": "Nmap identified 1 open service(s)",
                            "detail": "192.0.2.10:80 http nginx",
                            "recommendation": "",
                        }
                    ],
                }
            ],
        },
    }

    html = render(payload)

    assert "All observations and findings" in html
    assert "Nmap identified 1 open service(s)" in html
    assert "192.0.2.10:80 http nginx" in html


def test_html_shows_triage_and_owasp_limitations():
    payload = {
        "domain": "lab.local",
        "timestamp": "2026-09-09T00:00:00+00:00",
        "overall": {"total": 50, "max": 100, "risk_level": "INCONCLUSIVE"},
        "execution": {"assessment_mode": "identification-only"},
        "email": {},
        "web": {
            "total_score": 50,
            "authenticated": False,
            "owasp_coverage": [{
                "id": "A01:2025", "name": "Broken Access Control", "status": "PARTIAL",
                "evidence_modules": ["dast"], "limitations": ["No authenticated context."],
            }],
            "modules": [{
                "name": "dast", "findings": [{
                    "severity": "HIGH", "title": "SQL Injection", "detail": "HTTP 500",
                    "recommendation": "Validate", "verification_status": "POTENTIAL",
                    "confidence": "LOW", "occurrence_count": 2,
                }],
            }],
        },
    }
    html = render(payload)
    assert "OWASP Top 10:2025 coverage" in html
    assert "Broken Access Control" in html
    assert "Status: POTENTIAL" in html
    assert "Occurrences: 2" in html


def test_exact_host_web_report_uses_coherent_scope_and_coverage_labels():
    payload = {
        "domain": "portal.example.com",
        "timestamp": "2026-09-14T00:00:00+00:00",
        "overall": {"total": 72, "max": 100, "risk_level": "MEDIUM"},
        "execution": {"target_mode": "exact-host", "assessment_mode": "active-validation"},
        "email": {},
        "web": {
            "target_mode": "exact-host", "total_score": 72,
            "subdomains": [],
            "live_hosts": [{"url": "https://portal.example.com", "host": "portal.example.com"}],
            "modules": [{
                "name": "dast", "assessed": False,
                "findings": [{
                    "severity": "INFO", "title": "ZAP unavailable",
                    "verification_status": "TOOL_INCOMPLETE",
                }],
            }],
        },
    }

    html = render(payload)

    assert "Exact-host web assessment" in html
    assert "WEB POSTURE SCORE" in html
    assert "Email security" not in html
    assert "Discovered subdomains (0)" not in html
    assert "Subdomain discovery was intentionally not performed" in html
    assert "Coverage limitation:" in html
    assert "INCOMPLETE" in html
