"""Tests for the external-tool JSON parsers used by the web phase."""

from uncp_offsec.models import HostInfo
from uncp_offsec.web.content import wordlist_tuning
from uncp_offsec.web.cves import _CPE, _group_matches, _rows
from uncp_offsec.web.discovery import parse_output as parse_subfinder
from uncp_offsec.web.headers import _parse as parse_headers
from uncp_offsec.web.headers import _weak_csp
from uncp_offsec.web.ports import parse_naabu_json
from uncp_offsec.web.probe import parse_httpx_json
from uncp_offsec.web.tech import parse_whatweb_json
from uncp_offsec.web.tls import parse_testssl_json
from uncp_offsec.web.vulns import parse_nuclei_json


def test_subfinder_parse_dedupes_and_sorts():
    raw = "www.uncp.edu.pe\nUncp.Edu.Pe\nvpn.uncp.edu.pe\nwww.uncp.edu.pe\n"
    hosts = parse_subfinder(raw)
    assert hosts == ["uncp.edu.pe", "vpn.uncp.edu.pe", "www.uncp.edu.pe"]


def test_httpx_parse_prefers_https_variant():
    lines = [
        '{"host":"www.uncp.edu.pe","url":"http://www.uncp.edu.pe","status_code":302,"title":"Redir","tech":["nginx"],"webserver":"nginx","scheme":"http"}',
        '{"host":"www.uncp.edu.pe","url":"https://www.uncp.edu.pe","status_code":200,"title":"Hi","tech":["nginx","php"],"webserver":"nginx","scheme":"https"}',
    ]
    hosts = parse_httpx_json(lines)
    assert len(hosts) == 1
    assert hosts[0].scheme == "https"
    assert hosts[0].status == 200
    assert "php" in hosts[0].tech


def test_httpx_jsonest_drops_garbage():
    hosts = parse_httpx_json(['not json', '{"url":null}'])
    assert hosts == []


def test_naabu_parse():
    lines = [
        '{"host":"www.uncp.edu.pe","ip":"192.0.2.1","port":443,"protocol":"tcp"}',
        '{"host":"www.uncp.edu.pe","ip":"192.0.2.1","port":3306,"protocol":"tcp"}',
    ]
    entries = parse_naabu_json(lines)
    assert {e["port"] for e in entries} == {443, 3306}
    assert entries[0]["hostname"] == "www.uncp.edu.pe"
    assert entries[0]["host"] == "192.0.2.1"


def test_ffuf_tuning_uses_wordlist_size(tmp_path):
    quick = tmp_path / "quick.txt"
    quick.write_text("\n".join(f"path-{index}" for index in range(1500)), encoding="utf-8")
    large = tmp_path / "large.txt"
    large.write_text("\n".join(f"path-{index}" for index in range(10001)), encoding="utf-8")

    assert wordlist_tuning(quick) == (1500, 10, 5, 150)
    assert wordlist_tuning(large) == (10001, 5, 2, 2001)


def test_testssl_parse_extracts_entries():
    text = (
        '[{"id":"TLS1_1","severity":"HIGH","finding":"offers TLS1.1"},\n'
        '{"id":"TLS1_3","severity":"OK","finding":"offers TLS1.3"}]'
    )
    entries = parse_testssl_json(text)
    ids = {e["id"] for e in entries}
    assert "TLS1_1" in ids
    assert "TLS1_3" in ids


def test_whatweb_parse():
    raw = (
        '{"target":"https://www.uncp.edu.pe","http_status":200,"plugins":'
        '{"WordPress":{"version":"6.4","certainty":100},"X-Powered-By":[{}]}}'
    )
    parsed = parse_whatweb_json(raw)
    assert list(parsed) == ["https://www.uncp.edu.pe"]
    assert "WordPress" in parsed["https://www.uncp.edu.pe"]


def test_nuclei_parse_severity_mapping():
    lines = [
        '{"template-id":"exposed-panel","info":{"name":"Exposed panel","severity":"medium","tags":"exposure,panel"},"matched-at":"https://x.com"}',
        '{"template-id":"tech-detect","info":{"name":"Tech","severity":"info","tags":["tech","nginx"]}}',
        '{"template-id":"cve","info":{"name":"CVE-X","severity":"critical"}}',
    ]
    matches = parse_nuclei_json(lines)
    sevs = {m["name"]: m["severity"].value for m in matches}
    assert sevs["Exposed panel"] == "MEDIUM"
    assert sevs["Tech"] == "INFO"
    assert sevs["CVE-X"] == "CRITICAL"
    assert matches[0]["tags"] == ["exposure", "panel"]
    assert matches[1]["tags"] == ["tech", "nginx"]


def test_cve_rows_marks_kev_and_cvss():
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2026-0001", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}
        ]
    }
    rows = _rows(payload, {"CVE-2026-0001"})
    assert rows[0]["kev"] is True
    assert rows[0]["severity"] == "CRITICAL"


def test_nginx_uses_current_nvd_cpe_vendor():
    assert _CPE["nginx"].format(version="1.27.5") == (
        "cpe:2.3:a:f5:nginx:1.27.5:*:*:*:*:*:*:*"
    )


def test_cve_correlations_are_grouped_by_version_and_assets():
    correlated = {
        "id": "CVE-2026-0001", "product": "Apache", "version": "2.4.62",
        "score": 9.8, "severity": "CRITICAL", "kev": False, "url": "https://nvd.test",
    }
    first = HostInfo(url="https://a.example", host="a.example", cves=[dict(correlated)])
    second = HostInfo(url="https://b.example", host="b.example", cves=[dict(correlated)])

    grouped = _group_matches([first, second])

    assert len(grouped) == 1
    assert grouped[0]["hosts"] == {"a.example", "b.example"}


def test_header_parser_normalizes_header_names():
    assert parse_headers("HTTP/2 200\nStrict-Transport-Security: max-age=1\nX-Frame-Options: DENY\n") == {
        "strict-transport-security": "max-age=1",
        "x-frame-options": "DENY",
    }


def test_csp_with_only_upgrade_insecure_requests_is_weak():
    assert _weak_csp("upgrade-insecure-requests")
    assert not _weak_csp("default-src 'self'; script-src 'self'")
