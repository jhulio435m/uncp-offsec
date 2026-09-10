"""JSON writer for combined reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import CombinedScanResult


def build(payload: Any) -> dict:
    """Normalize any accepted payload into a combined report dict."""
    if isinstance(payload, CombinedScanResult):
        return payload.to_dict()
    if isinstance(payload, dict):
        if "email" in payload and "web" in payload and "overall" in payload:
            return payload
        if "modules" in payload:
            # A single-phase (MailSec-style) report dropped into the combined shape.
            raise ValueError("input is a single-phase report; use mailsec report instead")
        raise ValueError("unrecognized report payload")
    raise ValueError("unrecognized report payload")


def write(payload: Any, path: Path) -> None:
    path.write_text(json.dumps(build(payload), indent=2) + "\n", encoding="utf-8")