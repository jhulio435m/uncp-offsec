#!/usr/bin/env python3
"""Genera un informe HTML de ejemplo con el generador real de la plataforma.

Los datos son ilustrativos (dominio reservado .example e IP de documentación,
RFC 2606 y RFC 5737): no describen a ninguna organización. La web usa una
captura de este informe para mostrar cómo es el entregable.

    PYTHONPATH=src python web/scripts/sample-report.py salida.html
"""
import sys
from pathlib import Path

from uncp_offsec.reports.html import render

F = lambda sev, title, detail, rec, status, conf="HIGH", n=1: {
    "severity": sev, "title": title, "detail": detail, "recommendation": rec,
    "verification_status": status, "confidence": conf, "occurrence_count": n,
}

PAYLOAD = {
    "domain": "empresa.example",
    "timestamp": "2026-11-18T15:00:00+00:00",
    "overall": {"total": 61, "max": 100, "risk_level": "MEDIUM"},
    "execution": {"assessment_mode": "active-validation", "profile": "full", "elapsed_seconds": 1284},
    "email": {
        "total_score": 68,
        "modules": [
            {"name": "dmarc", "score": 10, "max": 25, "findings": [
                F("MEDIUM", "DMARC policy is p=none", "v=DMARC1; p=none; rua=mailto:dmarc@empresa.example",
                  "Review aggregate reports, then move to quarantine and reject.", "VALIDATED_NON_DESTRUCTIVE")]},
            {"name": "spf", "score": 20, "max": 20, "findings": [
                F("INFO", "SPF record ends in -all", "v=spf1 include:_spf.empresa.example -all", "", "OBSERVED")]},
            {"name": "mta_sts", "score": 0, "max": 10, "findings": [
                F("LOW", "MTA-STS policy not published", "No _mta-sts TXT record found.",
                  "Publish an MTA-STS policy in testing mode.", "VALIDATED_NON_DESTRUCTIVE")]},
        ],
    },
    "web": {
        "total_score": 58, "coverage_score": 84, "authenticated": False,
        "subdomains": ["www.empresa.example", "api.empresa.example", "tienda.empresa.example", "vpn.empresa.example"],
        "live_hosts": [
            {"url": "https://www.empresa.example", "ip": "192.0.2.10", "status": 200, "cdn": "",
             "tech_versions": {"nginx": "1.18.0"}, "cves": [], "headers": {"strict-transport-security": "1"}},
            {"url": "https://tienda.empresa.example", "ip": "192.0.2.14", "status": 200, "cdn": "",
             "tech_versions": {"Apache": "2.4.49"}, "cves": [{"id": "CVE-2021-41773"}], "headers": {}},
            {"url": "https://api.empresa.example", "ip": "198.51.100.7", "status": 401, "cdn": "",
             "tech": ["OpenAPI"], "cves": [], "headers": {"content-security-policy": "1"}},
        ],
        "coverage_metrics": {"unique_urls": 214, "unique_paths": 96, "unique_parameters": 41, "api_endpoints": 23,
                             "auth_endpoints": 4, "sensitive_endpoints": 6, "identifier_endpoints": 9, "forms": 12},
        "owasp_coverage": [
            {"id": "A01:2025", "name": "Broken Access Control", "status": "MANUAL_REQUIRED",
             "evidence_modules": ["anonymous"], "limitations": ["No credentials: IDOR/BOLA not confirmed."]},
            {"id": "A02:2025", "name": "Security Misconfiguration", "status": "PARTIAL",
             "evidence_modules": ["headers", "nuclei", "dast"], "limitations": ["Unauthenticated context only."]},
            {"id": "A03:2025", "name": "Software Supply Chain Failures", "status": "NOT_ASSESSED",
             "evidence_modules": [], "limitations": ["No source tree provided."]},
            {"id": "A05:2025", "name": "Injection", "status": "PARTIAL",
             "evidence_modules": ["sqli", "dast"], "limitations": ["GET parameters and authorized POST bodies only."]},
        ],
        "modules": [
            {"name": "nuclei", "findings": [
                F("HIGH", "Directory listing enabled", "https://tienda.empresa.example/backup/ returns an index page.",
                  "Disable autoindex and remove files that must not be public.", "VALIDATED_NON_DESTRUCTIVE")]},
            {"name": "cve", "findings": [
                F("HIGH", "Apache 2.4.49 matches CVE-2021-41773 (CISA KEV)",
                  "Version identified from the Server header and correlated with NVD. No exploitation attempted.",
                  "Upgrade to a fixed release or document the vendor backport.", "POTENTIAL", "MEDIUM")]},
            {"name": "headers", "findings": [
                F("MEDIUM", "Content-Security-Policy header missing", "Observed on 2 of 3 live hosts.",
                  "Define a policy and deploy it in report-only mode first.", "VALIDATED_NON_DESTRUCTIVE", "HIGH", 2)]},
            {"name": "ports", "findings": [
                F("MEDIUM", "Database service reachable from the Internet", "192.0.2.14:3306 mysql",
                  "Restrict access to the addresses that need it.", "VALIDATED_NON_DESTRUCTIVE")]},
            {"name": "anonymous", "findings": [
                F("INFO", "Cross-account access control not confirmed",
                  "At least two test accounts are required to evaluate IDOR/BOLA.",
                  "Provide two least-privilege test accounts.", "MANUAL_REQUIRED", "LOW")]},
        ],
    },
}

Path(sys.argv[1]).write_text(render(PAYLOAD), encoding="utf-8")
