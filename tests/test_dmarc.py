"""Tests for the DMARC module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mailsec.models import ScanConfig, Severity
from mailsec.modules import dmarc


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


@pytest.fixture
def config():
    return ScanConfig(domain="example.com", timeout=3)


@patch("dns.resolver.resolve")
def test_dmarc_reject_policy(mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer(
        ['v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com']
    )
    result, policy = dmarc.run(config)
    assert policy["p"] == "reject"
    assert any(x.severity == Severity.PASS and "p=reject" in x.title for x in result.findings)


@patch("dns.resolver.resolve")
def test_dmarc_none_flag(mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer(
        ['v=DMARC1; p=none; pct=100; rua=mailto:dmarc@example.com']
    )
    result, policy = dmarc.run(config)
    assert any(x.severity == Severity.HIGH and "p=none" in x.title for x in result.findings)


@patch("dns.resolver.resolve")
def test_missing_dmarc_critical(mock_resolve, config):
    import dns.exception

    mock_resolve.side_effect = dns.exception.DNSException
    result, policy = dmarc.run(config)
    assert any(x.severity == Severity.CRITICAL for x in result.findings)
    assert policy == {}


@patch("dns.resolver.resolve")
def test_partial_pct_warn(mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer(
        ['v=DMARC1; p=quarantine; pct=30; rua=mailto:dmarc@example.com']
    )
    result, policy = dmarc.run(config)
    assert any("pct=30" in x.title for x in result.findings)