"""Operator-configured stdio audit targets.

Most MCP servers ship as a command rather than a URL, so auditing only
streamable HTTP leaves most of the ecosystem unreachable. Running one means
executing the very code the audit exists to distrust, so the command never
comes from the model or from a case argument.

The operator writes a fixed table of named commands. A case selects a name.
There is no path from an audited server, a tool result or a model-supplied
string to an argument vector, because names are looked up, never parsed into
commands.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping

from .models import StdioTarget

STDIO_SCHEME = "stdio:"
_MAX_NAME_LENGTH = 64
_MAX_ARGS = 32


class StdioTargetError(ValueError):
    """Raised when a stdio target is unconfigured or malformed."""


def is_stdio_target(target_url: str) -> bool:
    return target_url.startswith(STDIO_SCHEME)


def stdio_target_name(target_url: str) -> str:
    if not is_stdio_target(target_url):
        raise StdioTargetError("target is not a stdio target")
    name = target_url[len(STDIO_SCHEME) :]
    if not name or len(name) > _MAX_NAME_LENGTH:
        raise StdioTargetError("stdio target name is empty or too long")
    if not all(character.isalnum() or character in "._-" for character in name):
        raise StdioTargetError("stdio target name is outside the allowed profile")
    return name


def parse_stdio_targets(raw: str | None) -> dict[str, StdioTarget]:
    """Parse an operator-owned target table.

    A JSON object whose values are argument arrays is the portable format. The
    original ``name=command arg;name=command`` form remains available for
    concise POSIX deployments. No shell is involved at parse or launch time.
    """

    if not raw:
        return {}
    if raw.lstrip().startswith("{"):
        return _parse_structured_targets(raw)
    targets: dict[str, StdioTarget] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        name, separator, command_line = entry.partition("=")
        name = name.strip()
        if not separator or not name:
            raise StdioTargetError("stdio target entry must be name=command")
        if name in targets:
            raise StdioTargetError(f"duplicate stdio target name: {name}")
        stdio_target_name(f"{STDIO_SCHEME}{name}")
        parts = shlex.split(command_line.strip())
        if not parts:
            raise StdioTargetError(f"stdio target {name} has no command")
        if len(parts) - 1 > _MAX_ARGS:
            raise StdioTargetError(f"stdio target {name} has too many arguments")
        targets[name] = StdioTarget(name=name, command=parts[0], args=parts[1:])
    return targets


def _parse_structured_targets(raw: str) -> dict[str, StdioTarget]:
    def reject_duplicate_names(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for name, command in pairs:
            if name in value:
                raise StdioTargetError(f"duplicate stdio target name: {name}")
            value[name] = command
        return value

    try:
        configured = json.loads(raw, object_pairs_hook=reject_duplicate_names)
    except (json.JSONDecodeError, TypeError) as exc:
        raise StdioTargetError("stdio target JSON is invalid") from exc
    if not isinstance(configured, dict):
        raise StdioTargetError("stdio target JSON must be an object")

    targets: dict[str, StdioTarget] = {}
    for name, parts in configured.items():
        if not isinstance(name, str):
            raise StdioTargetError("stdio target names must be strings")
        stdio_target_name(f"{STDIO_SCHEME}{name}")
        if (
            not isinstance(parts, list)
            or not parts
            or not all(isinstance(part, str) for part in parts)
        ):
            raise StdioTargetError(
                f"stdio target {name} must be a non-empty JSON string array"
            )
        if len(parts) - 1 > _MAX_ARGS:
            raise StdioTargetError(f"stdio target {name} has too many arguments")
        if not parts[0] or any("\0" in part for part in parts):
            raise StdioTargetError(f"stdio target {name} has an invalid command")
        targets[name] = StdioTarget(
            name=name,
            command=parts[0],
            args=parts[1:],
        )
    return targets


def resolve_stdio_target(
    target_url: str,
    configured: Mapping[str, StdioTarget],
) -> StdioTarget:
    name = stdio_target_name(target_url)
    target = configured.get(name)
    if target is None:
        raise StdioTargetError(
            f"stdio target {name} is not configured on this Airlock deployment"
        )
    return target
