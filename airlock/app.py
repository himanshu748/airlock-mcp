from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import AuditExecutor
from .canaries import CanaryVault
from .case_service import CaseService
from .control import TargetResolver, _system_resolver, create_control_server
from .fixtures import (
    DishonestBehaviors,
    StoreFixtureObserver,
    create_dishonest_server,
    create_honest_server,
)
from .models import EvidenceMode, ObservationCapabilities, TargetBinding
from .proxy import create_proxy_router
from .store import CaseIntegrityError, JsonCaseStore


_DOWNLOADABLE_ARTIFACTS = frozenset(
    {
        "airlock-report.json",
        "airlock-policy.json",
        "airlock-connector.json",
    }
)


class _BearerPathMiddleware:
    def __init__(self, app: ASGIApp, *, token: str, path_prefix: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}"
        self.path_prefix = path_prefix.rstrip("/")

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        path = str(scope.get("path", ""))
        is_protected_request = path == self.path_prefix or path.startswith(
            f"{self.path_prefix}/"
        )
        if scope["type"] == "http" and is_protected_request:
            supplied_values = Headers(scope=scope).getlist("authorization")
            supplied = supplied_values[0] if len(supplied_values) == 1 else ""
            if not secrets.compare_digest(supplied, self.expected):
                response = Response(
                    "Unauthorized",
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def create_app(
    *,
    case_root: Path | str,
    public_base_url: str,
    upstream_transport_factory: (
        Callable[[TargetBinding], httpx.BaseTransport] | None
    ) = None,
    proxy_upstream_headers: Mapping[str, str] | None = None,
    authenticated_target_urls: Sequence[str] | None = None,
    control_allowed_hosts: Sequence[str] | None = None,
    control_allowed_origins: Sequence[str] | None = None,
    control_bearer_token: str | None = None,
    case_proxy_bearer_token: str | None = None,
    fixture_bearer_token: str | None = None,
    state_integrity_key: str | bytes | None = None,
    target_resolver: TargetResolver = _system_resolver,
    allow_local_targets: bool = False,
    allowed_target_hostnames: Sequence[str] | None = None,
    observation_capabilities_by_mode: Mapping[
        EvidenceMode, ObservationCapabilities
    ]
    | None = None,
    observation_target_urls_by_mode: Mapping[
        EvidenceMode, Sequence[str]
    ]
    | None = None,
    max_control_request_bytes: int = 1024 * 1024,
    max_proxy_request_bytes: int = 1024 * 1024,
    max_proxy_response_bytes: int = 4 * 1024 * 1024,
    max_inventory_pages: int = 64,
    max_inventory_tools: int = 512,
    max_catalog_bytes: int = 2 * 1024 * 1024,
    max_audit_response_bytes: int = 4 * 1024 * 1024,
    audit_operation_timeout_seconds: float = 60.0,
    audit_total_timeout_seconds: float = 240.0,
    probe_planning_timeout_seconds: float = 5.0,
    probe_planning_memory_bytes: int = 512 * 1024 * 1024,
    max_runtime_events: int = 2_000,
    proxy_read_timeout_seconds: float = 60.0,
    max_runtime_stream_seconds: float = 300.0,
    mount_owned_fixtures: bool = False,
    fixture_root: Path | str | None = None,
    dishonest_fixture_behaviors: DishonestBehaviors | None = None,
) -> FastAPI:
    if control_bearer_token == "":
        raise ValueError("control_bearer_token cannot be empty")
    if case_proxy_bearer_token == "":
        raise ValueError("case_proxy_bearer_token cannot be empty")
    if fixture_bearer_token == "":
        raise ValueError("fixture_bearer_token cannot be empty")
    if mount_owned_fixtures and fixture_bearer_token is None:
        raise ValueError("owned fixtures require fixture_bearer_token")
    normalized_target_hosts = (
        [allowed_target_hostnames]
        if isinstance(allowed_target_hostnames, str)
        else list(allowed_target_hostnames or [])
    )
    normalized_authenticated_targets = (
        [authenticated_target_urls]
        if isinstance(authenticated_target_urls, str)
        else list(authenticated_target_urls or [])
    )
    if proxy_upstream_headers and not normalized_authenticated_targets:
        raise ValueError(
            "global upstream headers require at least one exact authenticated target URL"
        )
    if normalized_authenticated_targets and not proxy_upstream_headers:
        raise ValueError(
            "authenticated target URLs require configured upstream headers"
        )
    store = JsonCaseStore(case_root, integrity_key=state_integrity_key)
    case_service = CaseService(
        store,
        public_base_url=public_base_url,
        target_resolver=target_resolver,
        allow_local_targets=allow_local_targets,
        allowed_target_hostnames=normalized_target_hosts or None,
        credential_target_urls=(
            normalized_authenticated_targets or None
        ),
    )
    audit_executor = AuditExecutor(
        case_service,
        target_headers=proxy_upstream_headers,
        fixture_signing_key=(
            fixture_bearer_token if mount_owned_fixtures else None
        ),
        max_inventory_pages=max_inventory_pages,
        max_inventory_tools=max_inventory_tools,
        max_catalog_bytes=max_catalog_bytes,
        max_audit_response_bytes=max_audit_response_bytes,
        audit_operation_timeout_seconds=audit_operation_timeout_seconds,
        audit_total_timeout_seconds=audit_total_timeout_seconds,
        probe_planning_timeout_seconds=probe_planning_timeout_seconds,
        probe_planning_memory_bytes=probe_planning_memory_bytes,
    )
    configured_observation_modes = dict(
        observation_capabilities_by_mode
        or {
            EvidenceMode.TRANSCRIPT_ONLY: ObservationCapabilities(
                mcp_traffic=True,
                tool_results=True,
                server_egress=False,
                server_filesystem=False,
            )
        }
    )
    configured_observation_targets = {
        mode: list(urls)
        for mode, urls in (observation_target_urls_by_mode or {}).items()
    }
    if mount_owned_fixtures:
        configured_observation_modes[EvidenceMode.CONTROLLED_FIXTURE] = (
            ObservationCapabilities.controlled_fixture()
        )
        fixture_base_url = public_base_url.rstrip("/")
        configured_observation_targets[EvidenceMode.CONTROLLED_FIXTURE] = [
            f"{fixture_base_url}/fixtures/honest/mcp",
            f"{fixture_base_url}/fixtures/dishonest/mcp",
        ]
    control_server = create_control_server(
        store=store,
        case_service=case_service,
        audit_executor=audit_executor,
        observation_capabilities_by_mode=configured_observation_modes,
        observation_target_urls_by_mode=configured_observation_targets,
        proxy_authorization=(
            f"Bearer {case_proxy_bearer_token}"
            if case_proxy_bearer_token is not None
            else None
        ),
    )
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(
            control_allowed_hosts
            or ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        ),
        allowed_origins=list(
            control_allowed_origins
            or [
                "http://127.0.0.1:*",
                "http://localhost:*",
                "http://[::1]:*",
            ]
        ),
    )
    control_http_app = control_server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=False,
        max_request_body_size=max_control_request_bytes,
        transport_security=transport_security,
    )
    honest_fixture_server = None
    dishonest_fixture_server = None
    honest_fixture_http_app = None
    dishonest_fixture_http_app = None
    if mount_owned_fixtures:
        fixture_path = Path(fixture_root or Path(case_root).parent / "fixtures")
        fixture_base_url = public_base_url.rstrip("/")
        fixture_target_urls = {
            f"{fixture_base_url}/fixtures/honest/mcp",
            f"{fixture_base_url}/fixtures/dishonest/mcp",
        }
        observer = StoreFixtureObserver(
            store,
            signing_key=fixture_bearer_token,
            allowed_target_urls=fixture_target_urls,
        )
        honest_fixture_server = create_honest_server(
            observer=observer,
            workspace=fixture_path / "honest",
        )
        dishonest_fixture_server = create_dishonest_server(
            observer=observer,
            workspace=fixture_path / "dishonest",
            behaviors=dishonest_fixture_behaviors
            or DishonestBehaviors(
                write_on_export=True,
                undeclared_egress=True,
                canary_exfiltration=True,
                scope_escape=True,
                injected_instructions=True,
            ),
            canary_provider=lambda case_id: CanaryVault(store).load(case_id),
        )
        honest_fixture_http_app = honest_fixture_server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=False,
            max_request_body_size=max_control_request_bytes,
            transport_security=transport_security,
        )
        dishonest_fixture_http_app = (
            dishonest_fixture_server.streamable_http_app(
                streamable_http_path="/mcp",
                stateless_http=False,
                max_request_body_size=max_control_request_bytes,
                transport_security=transport_security,
            )
        )
    proxy_upstream_transport_factory = upstream_transport_factory

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(control_server.session_manager.run())
            if honest_fixture_server is not None:
                await stack.enter_async_context(
                    honest_fixture_server.session_manager.run()
                )
            if dishonest_fixture_server is not None:
                await stack.enter_async_context(
                    dishonest_fixture_server.session_manager.run()
                )
            yield

    app = FastAPI(
        title="Airlock backend",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    if control_bearer_token is not None:
        app.add_middleware(
            _BearerPathMiddleware,
            token=control_bearer_token,
            path_prefix="/airlock-control",
        )
    if case_proxy_bearer_token is not None:
        app.add_middleware(
            _BearerPathMiddleware,
            token=case_proxy_bearer_token,
            path_prefix="/cases",
        )
    if fixture_bearer_token is not None:
        app.add_middleware(
            _BearerPathMiddleware,
            token=fixture_bearer_token,
            path_prefix="/fixtures",
        )
    app.state.case_store = store
    app.state.case_service = case_service
    app.state.audit_executor = audit_executor
    app.state.control_server = control_server
    app.state.proxy_upstream_transport_factory = (
        proxy_upstream_transport_factory
    )
    app.state.honest_fixture_server = honest_fixture_server
    app.state.dishonest_fixture_server = dishonest_fixture_server
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=proxy_upstream_transport_factory,
            upstream_headers=proxy_upstream_headers,
            credential_target_urls=normalized_authenticated_targets or None,
            target_resolver=target_resolver,
            allow_local_targets=allow_local_targets,
            allowed_target_hostnames=normalized_target_hosts or None,
            max_request_bytes=max_proxy_request_bytes,
            max_buffered_response_bytes=max_proxy_response_bytes,
            max_runtime_events=max_runtime_events,
            upstream_read_timeout_seconds=proxy_read_timeout_seconds,
            max_stream_duration_seconds=max_runtime_stream_seconds,
        )
    )

    @app.get("/cases/{case_id}/artifacts/{artifact_name}")
    async def download_case_artifact(
        case_id: str,
        artifact_name: str,
    ) -> Response:
        if artifact_name not in _DOWNLOADABLE_ARTIFACTS:
            return Response(status_code=404)
        try:
            artifact = store.read_artifact(case_id, artifact_name)
        except CaseIntegrityError:
            return Response(
                "Artifact integrity verification failed",
                status_code=409,
            )
        except (FileNotFoundError, ValueError):
            return Response(status_code=404)
        return Response(
            content=artifact,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": (
                    f'attachment; filename="{artifact_name}"'
                ),
                "X-Content-Type-Options": "nosniff",
            },
        )

    app.mount("/airlock-control", control_http_app)
    if honest_fixture_http_app is not None:
        app.mount("/fixtures/honest", honest_fixture_http_app)
    if dishonest_fixture_http_app is not None:
        app.mount("/fixtures/dishonest", dishonest_fixture_http_app)
    return app


__all__ = ["create_app"]
