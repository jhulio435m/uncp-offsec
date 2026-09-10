from uncp_offsec.compare import build


def test_compare_reports_assets_and_cves():
    previous = {"web": {"subdomains": ["old.example"], "live_hosts": [{"url": "https://old.example", "cves": []}]}}
    current = {"web": {"subdomains": ["new.example"], "live_hosts": [{"url": "https://new.example", "cves": [{"id": "CVE-2026-1"}]}]}}
    result = build(previous, current)
    assert result["new_subdomains"] == ["new.example"]
    assert result["new_cves"] == ["CVE-2026-1"]
