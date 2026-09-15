from mailsec.models import Finding, ModuleResult, Severity
from uncp_offsec.web.nmap import IDENTIFICATION_ONLY_VULN_SCRIPTS, _script_severity, parse_xml
from uncp_offsec.web.ports import reconcile_services
from uncp_offsec.web.tls import reconcile_nmap


def test_parse_nmap_xml_open_service():
    rows = parse_xml('<nmaprun><host><address addr="192.0.2.1"/><ports><port portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>')
    assert rows == [{"host": "192.0.2.1", "port": "443", "service": "https", "product": "nginx", "version": "1.24", "scripts": []}]


def test_parse_nmap_xml_script_output():
    rows = parse_xml('<nmaprun><host><address addr="192.0.2.1"/><ports><port portid="443"><state state="open"/><service name="https"/><script id="ssl-cert" output="valid certificate"/></port></ports></host></nmaprun>')
    assert rows[0]["scripts"] == [{"id": "ssl-cert", "output": "valid certificate"}]


def test_vulnerability_nse_is_identification_only():
    assert "vulners" in IDENTIFICATION_ONLY_VULN_SCRIPTS
    assert "exploit" not in IDENTIFICATION_ONLY_VULN_SCRIPTS


def test_vulners_cvss_sets_severity():
    assert _script_severity("vulners", "CVE-2025-0001 9.8") == Severity.CRITICAL


def test_port_guess_is_replaced_by_nmap_service_identity():
    ports = ModuleResult(name="ports", findings=[Finding(
        "ports", Severity.MEDIUM, "Potential MySQL exposure (3306/tcp)",
        "Open on: db.example", "", confidence="LOW", verification_status="POTENTIAL",
    )])
    nmap = ModuleResult(name="nmap")
    nmap.services = [{
        "host": "192.0.2.3", "port": "3306", "service": "mysql",
        "product": "MariaDB", "version": "11.8.9", "scripts": [],
    }]

    reconcile_services(ports, nmap)

    finding = ports.findings[0]
    assert finding.title == "Confirmed mysql MariaDB 11.8.9 exposure (3306/tcp)"
    assert finding.verification_status == "SERVICE_CONFIRMED"
    assert finding.confidence == "HIGH"


def test_tls_reconciliation_removes_only_proven_contradictions():
    tls = ModuleResult(name="tls", findings=[Finding(
        "tls", Severity.LOW, "[cepre.example] 3 TLS LOW issue(s)",
        "FS_KEMs: No KEMs offered\ncert_trust_wildcard: trust is via wildcard\nHSTS: not offered", "",
    )])
    nmap = ModuleResult(name="nmap")
    nmap.services = [{
        "aliases": "cepre.example", "scripts": [
            {"id": "ssl-cert", "output": "Subject Alternative Name: DNS:cepre.example"},
            {"id": "ssl-enum-ciphers", "output": "key exchange: X25519MLKEM768"},
        ],
    }]

    reconcile_nmap(tls, nmap)

    assert "HSTS: not offered" in tls.findings[0].detail
    assert "FS_KEMs" not in tls.findings[0].detail
    assert "cert_trust_wildcard" not in tls.findings[0].detail
    assert "1 TLS LOW issue(s)" in tls.findings[0].title
    assert tls.findings[-1].verification_status == "CROSS_ENGINE_RESOLVED"
