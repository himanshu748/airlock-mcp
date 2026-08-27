from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import socket
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from mcp.shared.inbound import (
    find_invalid_x_mcp_header,
    validate_mcp_param_headers,
    x_mcp_header_map,
)

from .auth_context import fingerprint_auth_context
from .models import (
    CaseStatus,
    EvidenceEvent,
    EventKind,
    TargetBinding,
    ToolDeclaration,
)
from .pinned_transport import create_pinned_httpx_transport
from .store import CaseIntegrityError, JsonCaseStore
from .target_policy import TargetValidationError, validate_target_url


_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_MCP_REQUEST_HEADERS = {
    "accept",
    "cache-control",
    "content-type",
    "last-event-id",
    "mcp-method",
    "mcp-name",
    "mcp-protocol-version",
    "mcp-session-id",
}

_MCP_RESPONSE_HEADERS = {
    "cache-control",
    "content-type",
    "mcp-protocol-version",
    "mcp-session-id",
    "retry-after",
}

_ALLOWED_RUNTIME_METHODS = frozenset(
    {
        # A modern client negotiates with server/discover before initialize.
        # Without it no real MCP client can complete a handshake through the
        # proxy at all. It is a read-only capability probe.
        "server/discover",
        "initialize",
        "notifications/cancelled",
        "notifications/initialized",
        "ping",
        "tools/call",
        "tools/list",
    }
)

_ALLOWED_SERVER_NOTIFICATIONS = frozenset(
    {
        "notifications/cancelled",
        "notifications/progress",
    }
)

_BASE64_PREFIX = "=?base64?"
_BASE64_SUFFIX = "?="
_UTF8_BOM = b"\xef\xbb\xbf"


class MalformedMcpHeader(ValueError):
    pass


class RuntimeStreamTimeoutError(TimeoutError):
    pass


class RuntimeStreamByteLimitError(ValueError):
    pass


class RuntimeStreamProtocolError(ValueError):
    pass


def decode_mcp_header(value: str) -> str:
    if not (value.startswith(_BASE64_PREFIX) and value.endswith(_BASE64_SUFFIX)):
        return value
    encoded = value[len(_BASE64_PREFIX) : -len(_BASE64_SUFFIX)]
    try:
        raw = base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise MalformedMcpHeader("invalid Base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise MalformedMcpHeader("noncanonical Base64")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MalformedMcpHeader("invalid UTF-8") from exc


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _system_resolver(hostname: str) -> list[str]:
    return sorted(
        {
            address[4][0]
            for address in socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        }
    )


def _forward_request_headers(
    request: Request,
    upstream_headers: Mapping[str, str],
) -> dict[str, str]:
    forwarded = {
        name: value
        for name, value in request.headers.items()
        if name.lower() in _MCP_REQUEST_HEADERS
        or name.lower().startswith("mcp-param-")
    }
    for name, value in upstream_headers.items():
        if name.lower() in _HOP_BY_HOP_HEADERS | {"host", "content-length", "cookie"}:
            continue
        forwarded[name] = value
    return forwarded


def _forward_response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        name: value
        for name, value in response.headers.items()
        if name.lower() in _MCP_RESPONSE_HEADERS
    }


def create_proxy_router(
    store: JsonCaseStore,
    *,
    upstream_transport_factory: (
        Callable[[TargetBinding], httpx.BaseTransport] | None
    ) = None,
    upstream_headers: Mapping[str, str] | None = None,
    credential_target_urls: Iterable[str] | None = None,
    target_resolver: Callable[[str], Iterable[str]] = _system_resolver,
    allow_local_targets: bool = False,
    allowed_target_hostnames: Iterable[str] | None = None,
    max_request_bytes: int = 1_048_576,
    max_buffered_response_bytes: int = 4_194_304,
    max_runtime_events: int = 2_000,
    upstream_read_timeout_seconds: float = 60.0,
    max_stream_duration_seconds: float = 300.0,
) -> APIRouter:
    if max_request_bytes <= 0:
        raise ValueError("max_request_bytes must be positive")
    if max_buffered_response_bytes <= 0:
        raise ValueError("max_buffered_response_bytes must be positive")
    if type(max_runtime_events) is not int or max_runtime_events <= 0:
        raise ValueError("max_runtime_events must be a positive integer")
    for name, value in {
        "upstream_read_timeout_seconds": upstream_read_timeout_seconds,
        "max_stream_duration_seconds": max_stream_duration_seconds,
    }.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"{name} must be a positive number")
    build_upstream_transport = (
        upstream_transport_factory or create_pinned_httpx_transport
    )
    configured_upstream_headers = dict(upstream_headers or {})
    configured_credential_targets = frozenset(credential_target_urls or [])
    if configured_upstream_headers and not configured_credential_targets:
        raise ValueError(
            "upstream headers require at least one exact credential target URL"
        )
    if configured_credential_targets and not configured_upstream_headers:
        raise ValueError("credential target URLs require configured upstream headers")
    configured_auth_fingerprint = fingerprint_auth_context(
        configured_upstream_headers
    )
    router = APIRouter()

    @router.api_route("/cases/{case_id}/mcp", methods=["POST", "GET", "DELETE"])
    async def proxy_mcp(case_id: str, request: Request) -> Response:
        try:
            store.case_directory(case_id)
        except ValueError:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": "Airlock case not found",
                    },
                },
                status_code=404,
            )
        try:
            case = store.load_case(case_id)
        except CaseIntegrityError:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32008,
                        "message": "Airlock case state failed integrity verification",
                    },
                },
                status_code=409,
            )
        except FileNotFoundError:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": "Airlock case not found",
                    },
                },
                status_code=404,
            )
        payload: Any = None
        tool_name: str | None = None
        if case.status != CaseStatus.SEALED_ALLOWED or not case.enforcement_active:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32002,
                        "message": "Airlock case is not sealed for runtime forwarding",
                        "data": {"case_id": case_id},
                    },
                }
            )
        if (
            configured_upstream_headers
            and case.target_url not in configured_credential_targets
        ):
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32010,
                        "message": (
                            "Target URL is outside the configured credential scope"
                        ),
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )
        if case.auth_context_fingerprint != configured_auth_fingerprint:
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32007,
                        "message": (
                            "Target authentication context changed after audit"
                        ),
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > max_request_bytes:
                        return JSONResponse(
                            {"detail": "MCP request exceeds the configured size limit"},
                            status_code=413,
                        )
                except ValueError:
                    return JSONResponse(
                        {"detail": "Invalid Content-Length header"},
                        status_code=400,
                    )
            body_parts: list[bytes] = []
            body_size = 0
            async for chunk in request.stream():
                body_size += len(chunk)
                if body_size > max_request_bytes:
                    return JSONResponse(
                        {"detail": "MCP request exceeds the configured size limit"},
                        status_code=413,
                    )
                body_parts.append(chunk)
            request_body = b"".join(body_parts)
            try:
                payload = json.loads(request_body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    },
                    status_code=400,
                )
            is_request = (
                isinstance(payload, dict)
                and isinstance(payload.get("method"), str)
                and (
                    "params" not in payload
                    or isinstance(payload.get("params"), dict)
                )
            )
            is_response = (
                isinstance(payload, dict)
                and "method" not in payload
                and "id" in payload
                and (("result" in payload) ^ ("error" in payload))
            )
            if (
                not isinstance(payload, dict)
                or payload.get("jsonrpc") != "2.0"
                or not (is_request or is_response)
            ):
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id") if isinstance(payload, dict) else None,
                        "error": {"code": -32600, "message": "Invalid Request"},
                    },
                    status_code=400,
                )
            routing_header_names = (
                "mcp-protocol-version",
                "mcp-method",
                "mcp-name",
            )
            if any(
                len(request.headers.getlist(name)) > 1
                for name in routing_header_names
            ):
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {
                            "code": -32020,
                            "message": "Duplicate MCP routing header",
                        },
                    },
                    status_code=400,
                )
            # The catalog, schemas and annotations in this case were
            # inventoried under one protocol version. Forwarding an approved
            # call under a different one would enforce a policy derived from a
            # surface that was never audited.
            # Only the header is compared. An initialize body carries the
            # version the client is requesting, not the one it settles on, so
            # refusing on that would break every real handshake.
            supplied_protocol = request.headers.get("mcp-protocol-version")
            if (
                supplied_protocol is not None
                and case.protocol_version is not None
                and supplied_protocol != case.protocol_version
            ):
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {
                            "code": -32021,
                            "message": (
                                "MCP protocol version does not match the "
                                "version this case was audited under"
                            ),
                            "data": {
                                "case_id": case_id,
                                "audited_protocol_version": (
                                    case.protocol_version
                                ),
                            },
                        },
                    },
                    status_code=409,
                )
            routing_headers_present = any(
                request.headers.get(name) is not None
                for name in ("mcp-method", "mcp-name")
            )
            modern_routing_required = (
                request.headers.get("mcp-protocol-version") == "2026-07-28"
            )
            if is_response and routing_headers_present:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {
                            "code": -32020,
                            "message": "MCP routing headers are invalid on a response",
                        },
                    },
                    status_code=400,
                )
            if is_request and (modern_routing_required or routing_headers_present):
                body_method = payload.get("method")
                header_method = request.headers.get("mcp-method")
                params = payload.get("params")
                body_name = params.get("name") if isinstance(params, dict) else None
                encoded_header_name = request.headers.get("mcp-name")
                try:
                    header_name = (
                        decode_mcp_header(encoded_header_name)
                        if encoded_header_name is not None
                        else None
                    )
                except MalformedMcpHeader:
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": payload.get("id"),
                            "error": {
                                "code": -32020,
                                "message": "Malformed MCP routing header",
                            },
                        },
                        status_code=400,
                    )
                method_mismatch = header_method != body_method
                name_mismatch = body_method == "tools/call" and header_name != body_name
                if method_mismatch or name_mismatch:
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": payload.get("id"),
                            "error": {
                                "code": -32020,
                                "message": (
                                    "MCP routing headers do not match the request body"
                                ),
                            },
                        },
                        status_code=400,
                    )
            if is_request and payload.get("method") not in _ALLOWED_RUNTIME_METHODS:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {
                            "code": -32011,
                            "message": (
                                "MCP method is outside the approved tool-only "
                                "connector surface"
                            ),
                        },
                    },
                    status_code=400,
                )
            if isinstance(payload, dict) and payload.get("method") == "tools/call":
                params = payload.get("params")
                tool_name = params.get("name") if isinstance(params, dict) else None
                if not isinstance(tool_name, str) or not tool_name:
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": payload.get("id"),
                            "error": {
                                "code": -32602,
                                "message": "tools/call requires a non-empty string name",
                            },
                        }
                    )
                approved = set(
                    case.decision.approved_tools if case.decision is not None else []
                )
                if (
                    tool_name not in approved
                ):
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": payload.get("id"),
                            "error": {
                                "code": -32001,
                                "message": "Tool blocked by Airlock policy",
                                "data": {"case_id": case_id, "tool": tool_name},
                            },
                        }
                    )
                raw_arguments = params.get("arguments", {})
                if not isinstance(raw_arguments, dict):
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": payload.get("id"),
                            "error": {
                                "code": -32602,
                                "message": "tools/call arguments must be an object",
                            },
                        },
                        status_code=400,
                    )
                supplied_param_headers: dict[str, str] = {}
                duplicated_param_header = False
                for raw_name, raw_value in request.scope.get("headers", []):
                    name = raw_name.decode("latin-1").lower()
                    if not name.startswith("mcp-param-"):
                        continue
                    if name in supplied_param_headers:
                        duplicated_param_header = True
                    supplied_param_headers[name] = raw_value.decode("latin-1")
                declaration = next(
                    (
                        item
                        for item in case.declared_tools
                        if item.name == tool_name
                    ),
                    None,
                )
                if declaration is None:
                    store.mark_incomplete(case_id)
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": payload.get("id"),
                            "error": {
                                "code": -32003,
                                "message": (
                                    "Approved tool is missing from the bound catalog"
                                ),
                            },
                        },
                        status_code=409,
                    )
                input_schema = declaration.input_schema
                modern_request = (
                    request.headers.get("mcp-protocol-version") == "2026-07-28"
                )
                if modern_request or supplied_param_headers:
                    invalid_header_schema = find_invalid_x_mcp_header(
                        input_schema
                    )
                    expected_param_headers = {
                        f"mcp-param-{token}".lower()
                        for token in x_mcp_header_map(input_schema).values()
                    }
                    unexpected_param_headers = (
                        set(supplied_param_headers) - expected_param_headers
                    )
                    param_rejection = validate_mcp_param_headers(
                        input_schema,
                        raw_arguments,
                        request.headers,
                    )
                    if (
                        duplicated_param_header
                        or invalid_header_schema is not None
                        or unexpected_param_headers
                        or param_rejection is not None
                    ):
                        return JSONResponse(
                            {
                                "jsonrpc": "2.0",
                                "id": payload.get("id"),
                                "error": {
                                    "code": -32020,
                                    "message": (
                                        "MCP parameter routing headers do not "
                                        "match the inventoried schema and request body"
                                    ),
                                },
                            },
                            status_code=400,
                        )
        else:
            request_body = b""

        try:
            validated = validate_target_url(
                case.target_url,
                resolver=target_resolver,
                allow_local=allow_local_targets,
                allowed_hostnames=allowed_target_hostnames,
            )
            binding = case.target_binding
            if binding is None or (
                validated.scheme != binding.scheme
                or validated.hostname != binding.hostname
                or validated.port != binding.port
                or set(validated.resolved_ips) != set(binding.resolved_ips)
            ):
                raise TargetValidationError("target DNS binding changed")
        except TargetValidationError:
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32004,
                        "message": "Upstream target binding changed after case creation",
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )

        runtime_probe_id: str | None = None
        if tool_name is not None and isinstance(payload, dict):
            params = payload.get("params")
            arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
            canonical_arguments = json.dumps(
                arguments,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
            runtime_probe_id = f"runtime_{uuid4().hex}"
            store.append_runtime_event(
                case_id,
                EvidenceEvent(
                    event_id=f"ev_{uuid4().hex}",
                    probe_id=runtime_probe_id,
                    tool=tool_name,
                    kind=EventKind.TOOL_CALL,
                    sensor="mcp_transcript",
                    details={
                        "request_id": payload.get("id"),
                        "request_digest": _digest(request_body),
                        "arguments_digest": _digest(canonical_arguments),
                    },
                ),
                max_runtime_events=max_runtime_events,
            )

        # The transport is built per request from the binding this case
        # validated. Injection replaces the transport, never the client, so a
        # caller cannot substitute one that skips DNS pinning and reaches an
        # address outside the validated binding.
        owns_request_client = True
        request_client = httpx.AsyncClient(
            transport=build_upstream_transport(binding),
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                connect=30.0,
                read=upstream_read_timeout_seconds,
                write=30.0,
                pool=30.0,
            ),
        )
        upstream_request = request_client.build_request(
            request.method,
            case.target_url,
            headers=_forward_request_headers(request, configured_upstream_headers),
            content=request_body if request.method == "POST" else None,
        )
        request_started_at = asyncio.get_running_loop().time()
        try:
            upstream_response = await asyncio.wait_for(
                request_client.send(
                    upstream_request,
                    stream=True,
                    follow_redirects=False,
                ),
                timeout=max_stream_duration_seconds,
            )
        except asyncio.TimeoutError:
            if owns_request_client:
                await request_client.aclose()
            if tool_name is not None and runtime_probe_id is not None:
                store.append_runtime_event(
                    case_id,
                    EvidenceEvent(
                        event_id=f"ev_{uuid4().hex}",
                        probe_id=runtime_probe_id,
                        tool=tool_name,
                        kind=EventKind.SENSOR_FAILURE,
                        sensor="mcp_transcript",
                        details={
                            "checks": [],
                            "failure_class": "upstream_total_timeout",
                        },
                    ),
                    max_runtime_events=max_runtime_events,
                )
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32014,
                        "message": "Upstream response exceeded the Airlock time limit",
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )
        except Exception:
            if owns_request_client:
                await request_client.aclose()
            if tool_name is not None and runtime_probe_id is not None:
                store.append_runtime_event(
                    case_id,
                    EvidenceEvent(
                        event_id=f"ev_{uuid4().hex}",
                        probe_id=runtime_probe_id,
                        tool=tool_name,
                        kind=EventKind.SENSOR_FAILURE,
                        sensor="mcp_transcript",
                        details={
                            "checks": [],
                            "failure_class": "upstream_transport",
                        },
                    ),
                    max_runtime_events=max_runtime_events,
                )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32009,
                        "message": "Upstream MCP transport failed",
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )
        response_content_type = upstream_response.headers.get("content-type", "")
        response_headers = _forward_response_headers(upstream_response)

        content_encoding = upstream_response.headers.get(
            "content-encoding",
            "identity",
        )
        if content_encoding.lower().strip() not in {"", "identity"}:
            await upstream_response.aclose()
            if owns_request_client:
                await request_client.aclose()
            if tool_name is not None and runtime_probe_id is not None:
                store.append_runtime_event(
                    case_id,
                    EvidenceEvent(
                        event_id=f"ev_{uuid4().hex}",
                        probe_id=runtime_probe_id,
                        tool=tool_name,
                        kind=EventKind.SENSOR_FAILURE,
                        sensor="mcp_transcript",
                        details={
                            "checks": [],
                            "failure_class": "encoded_response",
                        },
                    ),
                    max_runtime_events=max_runtime_events,
                )
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32013,
                        "message": (
                            "Encoded upstream responses are outside the Airlock "
                            "runtime profile"
                        ),
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )

        if 300 <= upstream_response.status_code < 400:
            await upstream_response.aclose()
            if owns_request_client:
                await request_client.aclose()
            if tool_name is not None and runtime_probe_id is not None:
                store.append_runtime_event(
                    case_id,
                    EvidenceEvent(
                        event_id=f"ev_{uuid4().hex}",
                        probe_id=runtime_probe_id,
                        tool=tool_name,
                        kind=EventKind.SENSOR_FAILURE,
                        sensor="mcp_transcript",
                        details={
                            "checks": [],
                            "failure_class": "upstream_redirect",
                        },
                    ),
                    max_runtime_events=max_runtime_events,
                )
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32006,
                        "message": "Upstream redirects are not permitted by Airlock",
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )

        if (
            "text/event-stream" in response_content_type.lower()
            and not (
                isinstance(payload, dict)
                and payload.get("method") == "tools/list"
            )
        ):
            response_status = upstream_response.status_code

            async def stream_upstream():
                response_hasher = hashlib.sha256()
                response_bytes = 0
                filter_state = {
                    "raw_response_bytes": 0,
                    "filtered_server_messages": 0,
                }
                completed = False
                stream_failure_class: str | None = None
                try:
                    if upstream_response.is_stream_consumed:
                        chunks = [upstream_response.content]
                    else:
                        chunks = upstream_response.aiter_raw()
                    bounded_chunks = _bounded_stream_chunks(
                        chunks,
                        idle_timeout_seconds=upstream_read_timeout_seconds,
                        total_timeout_seconds=_remaining_response_seconds(
                            request_started_at,
                            max_stream_duration_seconds,
                        ),
                    )
                    async for chunk in _filter_sse_chunks(
                        bounded_chunks,
                        state=filter_state,
                        max_raw_bytes=max_buffered_response_bytes,
                        on_filtered=lambda: store.mark_incomplete(case_id),
                    ):
                        response_hasher.update(chunk)
                        response_bytes += len(chunk)
                        yield chunk
                    completed = stream_failure_class is None
                except RuntimeStreamByteLimitError:
                    stream_failure_class = "stream_byte_limit"
                except RuntimeStreamTimeoutError as exc:
                    stream_failure_class = str(exc)
                except RuntimeStreamProtocolError:
                    stream_failure_class = "stream_protocol_policy"
                except Exception:
                    stream_failure_class = "stream_transport_failure"
                finally:
                    await upstream_response.aclose()
                    if owns_request_client:
                        await request_client.aclose()
                    if tool_name is not None and runtime_probe_id is not None:
                        store.append_runtime_event(
                            case_id,
                            EvidenceEvent(
                                event_id=f"ev_{uuid4().hex}",
                                probe_id=runtime_probe_id,
                                tool=tool_name,
                                kind=(
                                    EventKind.SENSOR_FAILURE
                                    if stream_failure_class is not None
                                    else EventKind.TOOL_RESULT
                                ),
                                sensor="mcp_transcript",
                                details={
                                    "status_code": response_status,
                                    "content_type": response_content_type,
                                    "response_digest": (
                                        f"sha256:{response_hasher.hexdigest()}"
                                    ),
                                    "response_bytes": response_bytes,
                                    "raw_response_bytes": filter_state[
                                        "raw_response_bytes"
                                    ],
                                    "filtered_server_messages": filter_state[
                                        "filtered_server_messages"
                                    ],
                                    "stream_complete": completed,
                                    **(
                                        {
                                            "checks": [],
                                            "failure_class": stream_failure_class,
                                        }
                                        if stream_failure_class is not None
                                        else {}
                                    ),
                                },
                            ),
                            max_runtime_events=max_runtime_events,
                        )
                    if (
                        stream_failure_class is not None
                        or filter_state["filtered_server_messages"] > 0
                    ):
                        store.mark_incomplete(case_id)

            return StreamingResponse(
                stream_upstream(),
                status_code=response_status,
                headers=response_headers,
                media_type=None,
            )

        response_parts: list[bytes] = []
        response_size = 0
        buffered_failure_class: str | None = None
        try:
            if upstream_response.is_stream_consumed:
                chunks = [upstream_response.content]
            else:
                chunks = upstream_response.aiter_raw()
            async for chunk in _bounded_stream_chunks(
                chunks,
                idle_timeout_seconds=upstream_read_timeout_seconds,
                total_timeout_seconds=_remaining_response_seconds(
                    request_started_at,
                    max_stream_duration_seconds,
                ),
            ):
                response_size += len(chunk)
                if response_size > max_buffered_response_bytes:
                    if tool_name is not None and runtime_probe_id is not None:
                        store.append_runtime_event(
                            case_id,
                            EvidenceEvent(
                                event_id=f"ev_{uuid4().hex}",
                                probe_id=runtime_probe_id,
                                tool=tool_name,
                                kind=EventKind.SENSOR_FAILURE,
                                sensor="mcp_transcript",
                                details={
                                    "checks": [],
                                    "failure_class": "response_byte_limit",
                                    "response_bytes_observed": response_size,
                                },
                            ),
                            max_runtime_events=max_runtime_events,
                        )
                    store.mark_incomplete(case_id)
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": (
                                payload.get("id")
                                if isinstance(payload, dict)
                                else None
                            ),
                            "error": {
                                "code": -32005,
                                "message": (
                                    "Upstream response exceeds the Airlock buffer limit"
                                ),
                                "data": {"case_id": case_id},
                            },
                        },
                        status_code=502,
                    )
                response_parts.append(chunk)
        except RuntimeStreamTimeoutError as exc:
            buffered_failure_class = str(exc)
        finally:
            await upstream_response.aclose()
            if owns_request_client:
                await request_client.aclose()
        if buffered_failure_class is not None:
            if tool_name is not None and runtime_probe_id is not None:
                store.append_runtime_event(
                    case_id,
                    EvidenceEvent(
                        event_id=f"ev_{uuid4().hex}",
                        probe_id=runtime_probe_id,
                        tool=tool_name,
                        kind=EventKind.SENSOR_FAILURE,
                        sensor="mcp_transcript",
                        details={
                            "checks": [],
                            "failure_class": buffered_failure_class,
                            "response_bytes_observed": response_size,
                        },
                    ),
                    max_runtime_events=max_runtime_events,
                )
            store.mark_incomplete(case_id)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32014,
                        "message": "Upstream response exceeded the Airlock time limit",
                        "data": {"case_id": case_id},
                    },
                },
                status_code=502,
            )
        response_body = b"".join(response_parts)

        if "text/event-stream" in response_content_type.lower():
            try:
                response_body, filtered_server_messages = _filter_sse_payload(
                    response_body
                )
            except RuntimeStreamProtocolError:
                filtered_server_messages = 1
            if filtered_server_messages > 0:
                store.mark_incomplete(case_id)
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id") if isinstance(payload, dict) else None,
                        "error": {
                            "code": -32012,
                            "message": (
                                "Upstream server message is outside the approved "
                                "tool-only connector surface"
                            ),
                            "data": {"case_id": case_id},
                        },
                    },
                    status_code=502,
                )

        if response_body:
            try:
                buffered_message = json.loads(response_body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                buffered_message = None
            buffered_messages = (
                buffered_message
                if isinstance(buffered_message, list)
                else [buffered_message]
            )
            if any(
                isinstance(message, dict)
                and isinstance(message.get("method"), str)
                for message in buffered_messages
            ):
                store.mark_incomplete(case_id)
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id") if isinstance(payload, dict) else None,
                        "error": {
                            "code": -32012,
                            "message": (
                                "Upstream server request is outside the approved "
                                "tool-only connector surface"
                            ),
                            "data": {"case_id": case_id},
                        },
                    },
                    status_code=502,
                )

        if (
            isinstance(payload, dict)
            and payload.get("method") == "tools/list"
        ):
            try:
                response_payload = _decode_mcp_response(
                    response_body,
                    content_type=response_content_type,
                )
                result = response_payload.get("result", {})
                raw_tools = result.get("tools", [])
                inventoried = {tool.name: tool for tool in case.declared_tools}
                catalog_changed = False
                seen_names: set[str] = set()
                for raw_tool in raw_tools:
                    if not isinstance(raw_tool, dict) or not isinstance(
                        raw_tool.get("name"), str
                    ):
                        catalog_changed = True
                        break
                    if raw_tool["name"] in seen_names:
                        catalog_changed = True
                        break
                    seen_names.add(raw_tool["name"])
                    current = ToolDeclaration(
                        name=raw_tool["name"],
                        description=raw_tool.get("description", ""),
                        input_schema=raw_tool.get("inputSchema", {}),
                        annotations=raw_tool.get("annotations", {}),
                    )
                    expected = inventoried.get(current.name)
                    if expected is None or current != expected:
                        catalog_changed = True
                        break
                request_params = payload.get("params")
                request_cursor = (
                    request_params.get("cursor")
                    if isinstance(request_params, dict)
                    else None
                )
                if (
                    request_cursor is None
                    and result.get("nextCursor") is None
                    and seen_names != set(inventoried)
                ):
                    catalog_changed = True
            except (TypeError, ValueError, AttributeError):
                catalog_changed = True

            if catalog_changed:
                store.mark_incomplete(case_id)
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "error": {
                            "code": -32003,
                            "message": (
                                "Upstream tool catalog changed after Airlock approval"
                            ),
                            "data": {"case_id": case_id},
                        },
                    }
                )

        if tool_name is not None and runtime_probe_id is not None:
            store.append_runtime_event(
                case_id,
                EvidenceEvent(
                    event_id=f"ev_{uuid4().hex}",
                    probe_id=runtime_probe_id,
                    tool=tool_name,
                    kind=EventKind.TOOL_RESULT,
                    sensor="mcp_transcript",
                    details={
                        "status_code": upstream_response.status_code,
                        "content_type": response_content_type,
                        "response_digest": _digest(response_body),
                        "response_bytes": len(response_body),
                        "stream_complete": True,
                    },
                ),
                max_runtime_events=max_runtime_events,
            )

        return Response(
            content=response_body,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=None,
        )

    return router


def _decode_mcp_response(payload: bytes, *, content_type: str) -> dict[str, Any]:
    if "text/event-stream" not in content_type.lower():
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ValueError("MCP response must be an object")
        return decoded

    data_lines: list[str] = []
    for raw_line in payload.decode("utf-8").splitlines():
        if raw_line.startswith("data:"):
            data_lines.append(raw_line[5:].lstrip())
            continue
        if raw_line == "" and data_lines:
            candidate = json.loads("\n".join(data_lines))
            if isinstance(candidate, dict) and isinstance(
                candidate.get("result"), dict
            ):
                return candidate
            data_lines = []
    if data_lines:
        candidate = json.loads("\n".join(data_lines))
        if isinstance(candidate, dict):
            return candidate
    raise ValueError("SSE response did not contain an MCP result")


async def _as_async_chunks(chunks):
    if hasattr(chunks, "__aiter__"):
        async for chunk in chunks:
            yield chunk
        return
    for chunk in chunks:
        yield chunk


async def _bounded_stream_chunks(
    chunks,
    *,
    idle_timeout_seconds: float,
    total_timeout_seconds: float,
):
    iterator = _as_async_chunks(chunks).__aiter__()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + total_timeout_seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise RuntimeStreamTimeoutError("stream_duration_limit")
        try:
            chunk = await asyncio.wait_for(
                iterator.__anext__(),
                timeout=min(idle_timeout_seconds, remaining),
            )
        except StopAsyncIteration:
            return
        except asyncio.TimeoutError as exc:
            failure_class = (
                "stream_duration_limit"
                if loop.time() >= deadline
                else "stream_idle_timeout"
            )
            raise RuntimeStreamTimeoutError(failure_class) from exc
        yield chunk


def _remaining_response_seconds(started_at: float, total_seconds: float) -> float:
    remaining = total_seconds - (asyncio.get_running_loop().time() - started_at)
    if remaining <= 0:
        raise RuntimeStreamTimeoutError("stream_duration_limit")
    return remaining


def _split_sse_frame(
    buffer: bytes,
    *,
    final: bool = False,
) -> tuple[bytes, bytes, bytes] | None:
    line_start = 0
    position = 0
    while position < len(buffer):
        byte = buffer[position]
        if byte == 0x0D:
            if position + 1 == len(buffer) and not final:
                return None
            ending_length = (
                2
                if position + 1 < len(buffer) and buffer[position + 1] == 0x0A
                else 1
            )
        elif byte == 0x0A:
            ending_length = 1
        else:
            position += 1
            continue

        if position == line_start:
            end = position + ending_length
            return buffer[:position], buffer[position:end], buffer[end:]
        position += ending_length
        line_start = position
    return None


def _sse_frame_is_allowed(frame: bytes) -> bool:
    try:
        text = frame.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeStreamProtocolError("SSE frame is not valid UTF-8") from exc

    data_lines: list[str] = []
    for line in text.splitlines():
        if line == "data":
            data_lines.append("")
        elif line.startswith("data:"):
            value = line[5:]
            data_lines.append(value[1:] if value.startswith(" ") else value)

    if not data_lines:
        return True

    try:
        message = json.loads("\n".join(data_lines))
    except json.JSONDecodeError as exc:
        raise RuntimeStreamProtocolError(
            "SSE data is not a JSON-RPC message"
        ) from exc
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise RuntimeStreamProtocolError("SSE data is not a JSON-RPC object")

    method = message.get("method")
    if isinstance(method, str):
        params = message.get("params")
        if params is not None and not isinstance(params, dict):
            raise RuntimeStreamProtocolError(
                "SSE JSON-RPC params must be an object"
            )
        if "id" in message:
            return False
        return method in _ALLOWED_SERVER_NOTIFICATIONS

    is_response = (
        "method" not in message
        and "id" in message
        and (("result" in message) ^ ("error" in message))
    )
    if not is_response:
        raise RuntimeStreamProtocolError("SSE JSON-RPC message shape is invalid")
    return True


def _filter_sse_payload(payload: bytes) -> tuple[bytes, int]:
    buffer = payload[len(_UTF8_BOM) :] if payload.startswith(_UTF8_BOM) else payload
    forwarded: list[bytes] = []
    filtered_server_messages = 0
    while (split := _split_sse_frame(buffer, final=True)) is not None:
        frame, separator, buffer = split
        if _sse_frame_is_allowed(frame):
            forwarded.append(frame + separator)
        else:
            filtered_server_messages += 1
    if buffer:
        if _sse_frame_is_allowed(buffer):
            forwarded.append(buffer)
        else:
            filtered_server_messages += 1
    return b"".join(forwarded), filtered_server_messages


async def _filter_sse_chunks(
    chunks,
    *,
    state: dict[str, int],
    max_raw_bytes: int,
    on_filtered: Callable[[], None] | None = None,
):
    buffer = b""
    async for chunk in chunks:
        state["raw_response_bytes"] += len(chunk)
        if state["raw_response_bytes"] > max_raw_bytes:
            raise RuntimeStreamByteLimitError("SSE stream exceeds the byte limit")
        buffer += chunk
        if state.get("bom_checked", 0) == 0:
            if len(buffer) < len(_UTF8_BOM) and _UTF8_BOM.startswith(buffer):
                continue
            if buffer.startswith(_UTF8_BOM):
                buffer = buffer[len(_UTF8_BOM) :]
            state["bom_checked"] = 1
        while (split := _split_sse_frame(buffer)) is not None:
            frame, separator, buffer = split
            if _sse_frame_is_allowed(frame):
                yield frame + separator
            else:
                state["filtered_server_messages"] += 1
                if on_filtered is not None:
                    on_filtered()

    while (split := _split_sse_frame(buffer, final=True)) is not None:
        frame, separator, buffer = split
        if _sse_frame_is_allowed(frame):
            yield frame + separator
        else:
            state["filtered_server_messages"] += 1
            if on_filtered is not None:
                on_filtered()
    if buffer:
        if _sse_frame_is_allowed(buffer):
            yield buffer
        else:
            state["filtered_server_messages"] += 1
            if on_filtered is not None:
                on_filtered()
