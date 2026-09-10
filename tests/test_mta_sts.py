"""Tests for the MTA-STS module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mailsec.models import ScanConfig, Severity
from mailsec.modules import mta_sts


def _fake_txt_answer(record: str):
    class _Str:
        def decode(self, errors=None):
            return record

    class _R:
        rdtype = 16
        strings = [_Str()]

    class _Resp:
        def __iter__(self):
            return iter([_R()])

    return _Resp()


@pytest.fixture
def config():
    return ScanConfig(domain="example.com", timeout=3)


@patch("dns.resolver.resolve")
@patch("urllib.request.urlopen")
def test_mta_sts_stsv1_record_and_policy(mock_urlopen, mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer("v=STSv1; id=20260908")

    mock_resp = MagicMock()
    mock_resp.read.return_value = b"version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n"
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    result = mta_sts.run(config)

    assert result.status == Severity.MEDIUM
    assert any(f.severity == Severity.INFO and "DNS record found" in f.title for f in result.findings)
    assert any(f.severity == Severity.MEDIUM and "mode: testing" in f.title for f in result.findings)
    assert any(f.severity == Severity.PASS and "max_age=86400" in f.title for f in result.findings)
    assert not any("not configured" in f.title.lower() for f in result.findings)


@patch("dns.resolver.resolve")
@patch("urllib.request.urlopen")
def test_mta_sts_enforce_policy(mock_urlopen, mock_resolve, config):
    mock_resolve.return_value = _fake_txt_answer("v=STSv1; id=20260908")

    mock_resp = MagicMock()
    mock_resp.read.return_value = b"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    result = mta_sts.run(config)

    assert any(f.severity == Severity.PASS and "mode: enforce" in f.title for f in result.findings)
    assert not any(f.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL) for f in result.findings)


@patch("dns.resolver.resolve")
def test_mta_sts_missing_record(mock_resolve, config):
    import dns.exception

    mock_resolve.side_effect = dns.exception.DNSException
    result = mta_sts.run(config)

    assert result.status == Severity.MEDIUM
    assert any("not configured" in f.title.lower() for f in result.findings)
