from __future__ import annotations

import hashlib
import hmac


def fixture_probe_signature(
    key: str | bytes,
    *,
    case_id: str,
    probe_id: str,
    tool: str,
) -> str:
    raw_key = key.encode("utf-8") if isinstance(key, str) else key
    if not raw_key:
        raise ValueError("fixture signing key cannot be empty")
    payload = "\0".join((case_id, probe_id, tool)).encode("utf-8")
    return hmac.new(raw_key, payload, hashlib.sha256).hexdigest()


__all__ = ["fixture_probe_signature"]
