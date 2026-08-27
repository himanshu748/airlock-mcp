from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI

from .app import create_app


def _boolean(
    environ: Mapping[str, str],
    name: str,
    *,
    default: bool = False,
) -> bool:
    raw = environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _csv(environ: Mapping[str, str], name: str) -> list[str] | None:
    raw = environ.get(name)
    if raw is None:
        return None
    values = [item.strip() for item in raw.split(",") if item.strip()]
    return values or None


def _positive_integer(
    environ: Mapping[str, str],
    name: str,
    *,
    default: int,
) -> int:
    try:
        value = int(environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _require_loopback_operator_ui(environ: Mapping[str, str], host: str) -> None:
    """The operator interface has no authentication, so refuse to expose it.

    Documenting a loopback boundary is not the same as holding one. Binding a
    non-loopback host with the interface enabled would let any reachable client
    enumerate and read case records, so this fails closed at startup.
    """
    insecure_development = _boolean(environ, "AIRLOCK_INSECURE_DEVELOPMENT")
    if not _boolean(
        environ,
        "AIRLOCK_ENABLE_OPERATOR_UI",
        default=insecure_development,
    ):
        return
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if host.lower() in {"localhost", ""}:
            return
        raise ValueError(
            "AIRLOCK_ENABLE_OPERATOR_UI requires a loopback AIRLOCK_HOST; "
            f"{host!r} is not a loopback address"
        )
    if not address.is_loopback:
        raise ValueError(
            "AIRLOCK_ENABLE_OPERATOR_UI requires a loopback AIRLOCK_HOST; "
            f"{host!r} is not a loopback address"
        )


def create_app_from_env(
    environ: Mapping[str, str] | None = None,
) -> FastAPI:
    values = os.environ if environ is None else environ
    host = values.get("AIRLOCK_HOST", "127.0.0.1")
    insecure_development = _boolean(
        values,
        "AIRLOCK_INSECURE_DEVELOPMENT",
    )
    case_root = Path(values.get("AIRLOCK_CASE_ROOT", "data/cases"))
    public_base_url = values.get(
        "AIRLOCK_PUBLIC_BASE_URL",
        "http://127.0.0.1:8000",
    )
    allowed_target_hostnames = _csv(
        values,
        "AIRLOCK_ALLOWED_TARGET_HOSTNAMES",
    )
    target_authorization = values.get("AIRLOCK_TARGET_AUTHORIZATION")
    if target_authorization == "":
        raise ValueError("AIRLOCK_TARGET_AUTHORIZATION cannot be empty")
    control_token = values.get("AIRLOCK_CONTROL_BEARER_TOKEN")
    runtime_token = values.get("AIRLOCK_CASE_PROXY_BEARER_TOKEN")
    state_integrity_key = values.get("AIRLOCK_STATE_INTEGRITY_KEY")
    if state_integrity_key == "":
        raise ValueError("AIRLOCK_STATE_INTEGRITY_KEY cannot be empty")
    if control_token is not None and runtime_token is not None:
        if control_token == runtime_token:
            raise ValueError("control and case proxy bearer tokens must be distinct")
    if insecure_development:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host.lower() == "localhost"
        if not is_loopback or target_authorization is not None:
            raise ValueError(
                "insecure development must be loopback-only and cannot use "
                "target authentication"
            )
    elif control_token is None or runtime_token is None:
        raise ValueError(
            "control and case proxy bearer tokens are required unless "
            "AIRLOCK_INSECURE_DEVELOPMENT is enabled"
        )
    elif state_integrity_key is None:
        raise ValueError(
            "AIRLOCK_STATE_INTEGRITY_KEY is required unless "
            "AIRLOCK_INSECURE_DEVELOPMENT is enabled"
        )
    # Also enforced per request in the app, because a caller can build the
    # application directly without going through run().
    _require_loopback_operator_ui(values, host)
    upstream_headers = (
        {"Authorization": target_authorization}
        if target_authorization is not None
        else None
    )
    fixture_root = values.get("AIRLOCK_FIXTURE_ROOT")
    return create_app(
        case_root=case_root,
        public_base_url=public_base_url,
        proxy_upstream_headers=upstream_headers,
        authenticated_target_urls=_csv(
            values,
            "AIRLOCK_AUTHENTICATED_TARGET_URLS",
        ),
        control_allowed_hosts=_csv(values, "AIRLOCK_CONTROL_ALLOWED_HOSTS"),
        control_allowed_origins=_csv(values, "AIRLOCK_CONTROL_ALLOWED_ORIGINS"),
        control_bearer_token=control_token,
        case_proxy_bearer_token=runtime_token,
        fixture_bearer_token=values.get("AIRLOCK_FIXTURE_BEARER_TOKEN"),
        state_integrity_key=state_integrity_key,
        allow_local_targets=_boolean(
            values,
            "AIRLOCK_ALLOW_LOCAL_TARGETS",
        ),
        allowed_target_hostnames=allowed_target_hostnames,
        max_control_request_bytes=_positive_integer(
            values,
            "AIRLOCK_MAX_CONTROL_REQUEST_BYTES",
            default=1024 * 1024,
        ),
        max_proxy_request_bytes=_positive_integer(
            values,
            "AIRLOCK_MAX_PROXY_REQUEST_BYTES",
            default=1024 * 1024,
        ),
        max_proxy_response_bytes=_positive_integer(
            values,
            "AIRLOCK_MAX_PROXY_RESPONSE_BYTES",
            default=4 * 1024 * 1024,
        ),
        max_inventory_pages=_positive_integer(
            values,
            "AIRLOCK_MAX_INVENTORY_PAGES",
            default=64,
        ),
        max_inventory_tools=_positive_integer(
            values,
            "AIRLOCK_MAX_INVENTORY_TOOLS",
            default=512,
        ),
        max_catalog_bytes=_positive_integer(
            values,
            "AIRLOCK_MAX_CATALOG_BYTES",
            default=2 * 1024 * 1024,
        ),
        max_audit_response_bytes=_positive_integer(
            values,
            "AIRLOCK_MAX_AUDIT_RESPONSE_BYTES",
            default=4 * 1024 * 1024,
        ),
        audit_operation_timeout_seconds=_positive_integer(
            values,
            "AIRLOCK_AUDIT_OPERATION_TIMEOUT_SECONDS",
            default=60,
        ),
        audit_total_timeout_seconds=_positive_integer(
            values,
            "AIRLOCK_AUDIT_TOTAL_TIMEOUT_SECONDS",
            default=240,
        ),
        probe_planning_timeout_seconds=_positive_integer(
            values,
            "AIRLOCK_PROBE_PLANNING_TIMEOUT_SECONDS",
            default=5,
        ),
        probe_planning_memory_bytes=_positive_integer(
            values,
            "AIRLOCK_PROBE_PLANNING_MEMORY_BYTES",
            default=512 * 1024 * 1024,
        ),
        max_runtime_events=_positive_integer(
            values,
            "AIRLOCK_MAX_RUNTIME_EVENTS",
            default=2_000,
        ),
        proxy_read_timeout_seconds=_positive_integer(
            values,
            "AIRLOCK_PROXY_READ_TIMEOUT_SECONDS",
            default=60,
        ),
        max_runtime_stream_seconds=_positive_integer(
            values,
            "AIRLOCK_MAX_RUNTIME_STREAM_SECONDS",
            default=300,
        ),
        enable_operator_ui=_boolean(
            values,
            "AIRLOCK_ENABLE_OPERATOR_UI",
            # On in development so the interface is never a silent 404.
            # Production must opt in, because it carries no auth of its own.
            default=insecure_development,
        ),
        mount_owned_fixtures=_boolean(
            values,
            "AIRLOCK_MOUNT_OWNED_FIXTURES",
        ),
        fixture_root=Path(fixture_root) if fixture_root else None,
    )


def run() -> None:
    import uvicorn

    host = os.environ.get("AIRLOCK_HOST", "127.0.0.1")
    port = _positive_integer(os.environ, "AIRLOCK_PORT", default=8000)
    _require_loopback_operator_ui(os.environ, host)
    uvicorn.run(create_app_from_env(), host=host, port=port)


__all__ = ["create_app_from_env", "run"]
