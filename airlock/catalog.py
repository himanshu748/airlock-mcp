from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from .models import ToolDeclaration


def compute_catalog_digest(declarations: Iterable[ToolDeclaration]) -> str:
    ordered = sorted(declarations, key=lambda item: item.name)
    canonical = json.dumps(
        [item.model_dump(mode="json") for item in ordered],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


__all__ = ["compute_catalog_digest"]
