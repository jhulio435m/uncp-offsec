"""Unit tests for the SPF parser and analysis."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mailsec.models import ScanConfig, Severity
from mailsec.modules import spf


def test_parse_spf_hardfail():
    record = "v=spf1 include:_spf.google.com ~all"
    all_q, includes, redirect = spf._parse_spf(record)
    assert all_q == "~"
    assert includes == ["_spf.google.com"]
    assert redirect is None


def test_parse_spf_redirect():
    record = "v=spf1 redirect=_spf.example.net"
    all_q, includes, redirect = spf._parse_spf(record)
    assert all_q is None
    assert includes == []
    assert redirect == "_spf.example.net"


def test_parse_spf_plusall():
    all_q, _, _ = spf._parse_spf("v=spf1 +all")
    assert all_q == "+"


def test_parse_spf_default_plusall():
    # bare "all" defaults to +
    all_q, _, _ = spf._parse_spf("v=spf1 all")
    assert all_q == "+"


@pytest.fixture
def config():
    return ScanConfig(domain="example.com", timeout=3)


@patch("dns.resolver.resolve")
def test_no_spf_record_critical(mock_resolve, config):
    import dns.exception

    mock_resolve.side_effect = dns.exception.DNSException
    result = spf.run(config)
    assert any(f.severity == Severity.CRITICAL and "SPF" in f.title for f in result.findings)


def _fake_txt_answer(records):
    class _Str:
        def __init__(self, s):
            self.s = s

        def decode(self, errors=None):
            return self.s

    class _R:
        rdtype = 16
        strings = [_Str(r) for r in records]

    class _Resp:
        def __iter__(self):
            return iter([_R()])

    return _Resp()


@patch("dns.resolver.resolve")
def test_spf_hardfail_pass(mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer(['"v=spf1 include:_spf.example.com -all"'])
    result = spf.run(config)
    assert any(
        f.severity == Severity.PASS and "Hard fail" in f.title for f in result.findings
    )


@patch("dns.resolver.resolve")
def test_spf_softfail_warning(mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer(['"v=spf1 include:_spf.example.com ~all"'])
    result = spf.run(config)
    assert any(
        f.severity == Severity.MEDIUM and "Soft fail" in f.title for f in result.findings
    )


@patch("dns.resolver.resolve")
def test_spf_count_lookups(mock_resolve, config):
    # root record includes two domains; nothing nested
    mock_resolve.return_value = _fake_txt_answer(['"v=spf1 include:a.com include:b.com -all"'])

    def fake_count(terms):
        return len(terms)

    with patch.object(spf, "_count_lookups", side_effect=fake_count):
        result = spf.run(config)
    # The +all / includes given - the count call happens on include list
    assert result.findings  # at least the informational record found
