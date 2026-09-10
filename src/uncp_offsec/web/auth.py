"""Load caller-supplied HTTP authentication material without reporting secrets."""

from __future__ import annotations

import json
from pathlib import Path


def load_headers(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read authentication header file: {exc}") from exc
    if not isinstance(raw, dict) or not raw:
        raise ValueError("authentication header file must be a non-empty JSON object")
    headers: dict[str, str] = {}
    forbidden = {"host", "content-length", "connection", "transfer-encoding"}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str) or not name.strip() or "\n" in value or "\r" in value:
            raise ValueError("authentication headers must be string names and single-line values")
        if name.strip().lower() in forbidden:
            raise ValueError(f"authentication header is not allowed: {name}")
        headers[name.strip()] = value
    return headers
