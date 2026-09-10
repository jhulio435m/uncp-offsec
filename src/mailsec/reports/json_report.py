"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import ScanResult

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "PASS": 5,
}


def _to_dict(payload: Any) -> dict:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, ScanResult):
        return payload.to_dict()
    return dict(payload)


def normalize_report(payload: Any) -> dict:
    """Convert a ScanResult (or already-dict) into a stable report dict."""
    data = _to_dict(payload)

    breakdown = getattr(payload, "breakdown", None) if not isinstance(payload, dict) else None
    if breakdown is not None:
        data.setdefault("risk", breakdown.to_dict())

    if "risk" not in data:
        # re-derive from dict if raw
        data.setdefault("risk", {"total": data.get("total_score", 0), "risk_level": data.get("risk_level", "UNKNOWN")})

    return data


def build(payload: Any) -> dict:
    return normalize_report(payload)


def write(payload: Any, path: Path) -> None:
    path.write_text(json.dumps(build(payload), indent=2) + "\n", encoding="utf-8")