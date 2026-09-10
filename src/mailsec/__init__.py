"""MailSec Auditor - Authorized email surface assessment tool."""

__version__ = "0.1.0"

from .models import Finding, ModuleResult, MXInfo, ScanConfig, ScanResult, Severity

__all__ = [
    "Finding",
    "MXInfo",
    "ModuleResult",
    "ScanConfig",
    "ScanResult",
    "Severity",
    "__version__",
]
