from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


ANONYMOUS_AUTH_CONTEXT = "sha256:anonymous"


def fingerprint_auth_context(headers: Mapping[str, str] | None) -> str:
    if not headers:
        return ANONYMOUS_AUTH_CONTEXT
    normalized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip().lower()
        value = str(raw_value)
        if not name:
            raise ValueError("target authentication header names must be non-empty")
        if name in normalized:
            raise ValueError(
                "target authentication headers must be unique ignoring case"
            )
        normalized[name] = value
    canonical = json.dumps(
        sorted(normalized.items()),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


__all__ = ["ANONYMOUS_AUTH_CONTEXT", "fingerprint_auth_context"]
