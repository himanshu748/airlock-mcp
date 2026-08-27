from __future__ import annotations

import json
import secrets
from collections.abc import Iterable
from typing import Any

from .store import JsonCaseStore


class CanaryVaultError(ValueError):
    pass


def redact_canaries(value: Any, canaries: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): redact_canaries(item, canaries)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_canaries(item, canaries) for item in value]
    if isinstance(value, tuple):
        return [redact_canaries(item, canaries) for item in value]
    if isinstance(value, str):
        redacted = value
        for label, canary in canaries.items():
            redacted = redacted.replace(canary, f"<airlock-canary:{label}>")
        return redacted
    return value


def redact_event_details(
    details: dict[str, Any],
    canaries: dict[str, str],
) -> dict[str, Any]:
    serialized = json.dumps(details, sort_keys=True, default=str)
    matched = sorted(
        label for label, value in canaries.items() if value in serialized
    )
    redacted = redact_canaries(details, canaries)
    if matched:
        redacted["matched_canary_ids"] = sorted(
            set(redacted.get("matched_canary_ids", [])) | set(matched)
        )
    return redacted


class CanaryVault:
    def __init__(self, store: JsonCaseStore) -> None:
        self.store = store

    def plant(self, case_id: str, *, labels: list[str]) -> dict[str, str]:
        if not labels or any(not label.strip() for label in labels):
            raise ValueError("canary labels must be non-empty")
        if len(labels) != len(set(labels)):
            raise ValueError("canary labels must be unique")
        planted = {
            label: f"airlock_canary_{secrets.token_urlsafe(24)}"
            for label in labels
        }
        self._write(case_id, planted)
        return planted

    def load(
        self,
        case_id: str,
        *,
        expected_labels: Iterable[str] | None = None,
    ) -> dict[str, str]:
        try:
            payload = json.loads(
                self.store.read_private_artifact(
                    case_id,
                    ".airlock-canaries.json",
                )
            )
        except json.JSONDecodeError as exc:
            raise CanaryVaultError("invalid canary vault") from exc
        if (
            not isinstance(payload, dict)
            or not payload
            or not all(
                isinstance(key, str)
                and bool(key.strip())
                and isinstance(value, str)
                and value.startswith("airlock_canary_")
                and len(value) >= 32
                for key, value in payload.items()
            )
            or len(payload.values()) != len(set(payload.values()))
        ):
            raise CanaryVaultError("invalid canary vault")
        if expected_labels is not None and set(payload) != set(expected_labels):
            raise CanaryVaultError("canary vault does not contain the expected labels")
        return payload

    def _write(self, case_id: str, planted: dict[str, str]) -> None:
        self.store.write_private_json(
            case_id,
            ".airlock-canaries.json",
            planted,
        )


__all__ = [
    "CanaryVault",
    "CanaryVaultError",
    "redact_canaries",
    "redact_event_details",
]
