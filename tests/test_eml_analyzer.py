"""Tests for the EML forensic analyzer."""

from __future__ import annotations

from pathlib import Path

from mailsec.models import Severity
from mailsec.modules import eml_analyzer

SAMPLE = """\
Return-Path: <attacker@evil.example>
Received: from mx1.corpbank.example (mx1.corpbank.example [203.0.113.7])
\tby mail.corpbank.example (Postfix) with ESMTP id ABC
Received: from relay.badsender.net (relay.badsender.net [198.51.100.9])
\tby mx1.corpbank.example with SMTP id DEF
Authentication-Results: mail.corpbank.example;
\tspf=softfail smtp.mailfrom=attacker@evil.example;
\tdmarc=fail (p=NONE dis=QUARANTINE) header.from=corpbank.example;
\tdkim=fail header.i=@corpbank.example
ARC-Authentication-Results: i=1; mail.corpbank.example;
\tspf=softfail smtp.mailfrom=attacker@evil.example;
\tdmarc=fail header.from=corpbank.example
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=corpbank.example; s=arc2024; b=x
From: "Banco" <gerencia@corpbank.example>
To: john@corpbank.example
Subject: Urgente
Message-ID: <x@evil.example>

Cuerpo.
"""


def test_parse_spoofed_message(tmp_path: Path):
    f = tmp_path / "phish.eml"
    f.write_text(SAMPLE)
    analysis, result = eml_analyzer.analyze(f)

    assert analysis.measured_spf == "softfail"
    assert analysis.measured_dkim == "fail"
    assert analysis.measured_dmarc == "fail"
    assert analysis.dmarc_disposition == "quarantine"
    assert analysis.return_path == "<attacker@evil.example>"

    # Return-path / From domain mismatch should be flagged
    assert any("Return-Path domain differs" in x.title for x in result.findings)


def test_suspicious_dmarc_fail_is_high(tmp_path: Path):
    f = tmp_path / "phish.eml"
    f.write_text(SAMPLE)
    _, result = eml_analyzer.analyze(f)
    assert any(
        x.severity == Severity.HIGH and "DMARC" in x.title for x in result.findings
    )


def test_missing_file_critical(tmp_path: Path):
    _, result = eml_analyzer.analyze(tmp_path / "nope.eml")
    assert any(x.severity == Severity.CRITICAL for x in result.findings)
