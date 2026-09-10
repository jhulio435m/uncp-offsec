from mailsec.models import Severity
from uncp_offsec.web.nmap import IDENTIFICATION_ONLY_VULN_SCRIPTS, _script_severity, parse_xml


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
