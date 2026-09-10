"""Tests for the DANE module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mailsec.models import MXInfo, ScanConfig, Severity
from mailsec.modules import dane


class _FakeTLSARecord:
    def __init__(self, usage: int, selector: int, mtype: int, cert: bytes):
        self.rdtype = 52
        self.usage = usage
        self.selector = selector
        self.mtype = mtype
        self.cert = cert


def _fake_tlsa_answer(records: list[_FakeTLSARecord]):
    class _Resp:
        def __iter__(self):
            return iter(records)

    return _Resp()


@pytest.fixture
def config():
    return ScanConfig(domain="example.com", timeout=3)


@pytest.fixture
def mx_hosts():
    return [MXInfo(hostname="mail.example.com", preference=10)]


@patch("dns.resolver.resolve")
def test_valid_tlsa_sha256(mock_resolve, config, mx_hosts):
    # Valid 32-byte SHA-256 association
    cert_hash = bytes.fromhex("faaf2d9a9d4f373469dc007efcd508cd22af485bdfda4019af961164c2047bff")
    mock_resolve.return_value = _fake_tlsa_answer([_FakeTLSARecord(3, 1, 1, cert_hash)])

    result = dane.run(config, mx_hosts)

    assert result.status == Severity.PASS
    assert any(f.severity == Severity.PASS and "valid TLSA record" in f.title for f in result.findings)
    assert not any("unusual" in f.title.lower() for f in result.findings)


@patch("dns.resolver.resolve")
def test_valid_tlsa_sha512(mock_resolve, config, mx_hosts):
    # Valid 64-byte SHA-512 association
    cert_hash = b"\xaa" * 64
    mock_resolve.return_value = _fake_tlsa_answer([_FakeTLSARecord(3, 1, 2, cert_hash)])

    result = dane.run(config, mx_hosts)

    assert result.status == Severity.PASS
    assert any(f.severity == Severity.PASS and "valid TLSA record" in f.title for f in result.findings)
    assert not any("unusual" in f.title.lower() for f in result.findings)


@patch("dns.resolver.resolve")
def test_unusual_hash_length_sha256(mock_resolve, config, mx_hosts):
    # Invalid SHA-256 hash length (only 20 bytes instead of 32)
    cert_hash = b"\xaa" * 20
    mock_resolve.return_value = _fake_tlsa_answer([_FakeTLSARecord(3, 1, 1, cert_hash)])

    result = dane.run(config, mx_hosts)

    assert result.status == Severity.LOW
    assert any(f.severity == Severity.LOW and "hash length unusual" in f.title for f in result.findings)
    assert not any(f.severity == Severity.PASS for f in result.findings)


@patch("dns.resolver.resolve")
def test_unusual_hash_length_sha512(mock_resolve, config, mx_hosts):
    # Invalid SHA-512 hash length (32 bytes instead of 64)
    cert_hash = b"\xaa" * 32
    mock_resolve.return_value = _fake_tlsa_answer([_FakeTLSARecord(3, 1, 2, cert_hash)])

    result = dane.run(config, mx_hosts)

    assert result.status == Severity.LOW
    assert any(f.severity == Severity.LOW and "hash length unusual" in f.title for f in result.findings)
    assert not any(f.severity == Severity.PASS for f in result.findings)


@patch("dns.resolver.resolve")
def test_malformed_tlsa_parameters(mock_resolve, config, mx_hosts):
    # Invalid usage (e.g. 99)
    cert_hash = b"\xaa" * 32
    mock_resolve.return_value = _fake_tlsa_answer([_FakeTLSARecord(99, 1, 1, cert_hash)])

    result = dane.run(config, mx_hosts)

    assert result.status == Severity.HIGH
    assert any(f.severity == Severity.HIGH and "malformed TLSA record" in f.title for f in result.findings)


def test_dane_no_mx_hosts(config):
    result = dane.run(config, [])
    assert result.status == Severity.INFO
    assert any("No MX hosts" in f.title for f in result.findings)


@patch("dns.resolver.resolve")
@patch("mailsec.modules.dane._check_dnssec", return_value=False)
def test_dane_not_configured(mock_dnssec, mock_resolve, config, mx_hosts):
    import dns.exception

    mock_resolve.side_effect = dns.exception.DNSException
    result = dane.run(config, mx_hosts)

    assert result.status == Severity.MEDIUM
    assert any("not configured" in f.title.lower() for f in result.findings)
