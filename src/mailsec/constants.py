"""Constants and reference data for MailSec Auditor."""

# RFC references used across modules
RFC = {
    "SPF": "RFC 7208 - Sender Policy Framework",
    "DKIM": "RFC 6376 - DomainKeys Identified Mail",
    "DKIM_KEY": "RFC 8301 - DKIM algorithm/key usage update",
    "DMARC": "RFC 9989 - DMARC (replaces RFC 7489)",
    "DMARC_REPORT": "RFC 9991 - DMARC failure reporting",
    "SMTP": "RFC 5321 - Simple Mail Transfer Protocol",
    "STARTTLS": "RFC 3207 - SMTP STARTTLS",
    "MTA_STS": "RFC 8461 - SMTP MTA Strict Transport Security",
    "TLS_RPT": "RFC 8460 - SMTP TLS Reporting",
    "DANE": "RFC 7672 - SMTP Security via DANE TLS",
    "DKIM_ARC": "RFC 8617 - Authenticated Received Chain",
}

# SPF hardcoded DNS lookup limit (RFC 7208 section 4.6.4)
SPF_MAX_DNS_LOOKUPS = 10

# DKIM key size limits (RFC 8301)
DKIM_MIN_RSA_KEY_BITS = 1024
DKIM_RECOMMENDED_RSA_KEY_BITS = 2048
DKIM_BANNED_HASHES = {"sha1"}

# Default network timeouts (seconds)
DEFAULT_TIMEOUT = 10.0
TLS_TIMEOUT = 15.0

# SMTP ports checked
SMTP_PORT = 25

# Scoring categories
SCORE_DOMAIN_AUTH_MAX = 40.0
SCORE_SMTP_TRANSPORT_MAX = 25.0
SCORE_ANTI_SPOOFING_MAX = 20.0
SCORE_INFRA_EXPOSURE_MAX = 10.0
SCORE_MONITORING_MAX = 5.0
SCORE_TOTAL_MAX = 100.0

# Risk thresholds
RISK_THRESHOLDS = [
    (0, 35.999, "CRITICAL"),
    (36, 55.999, "HIGH"),
    (56, 75.999, "MEDIUM"),
    (76, 90.999, "LOW"),
    (91, 100, "GOOD"),
]
