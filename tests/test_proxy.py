import asyncio
import gzip
import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from airlock.auth_context import fingerprint_auth_context
from airlock.case_service import CaseService
from airlock.detectors import detect_findings
from airlock.models import (
    DecisionChoice,
    DeclaredScope,
    EvidenceMode,
    ObservationCapabilities,
    EventKind,
    ProbeRecord,
    TargetBinding,
    ToolDeclaration,
)
from airlock.proxy import _filter_sse_chunks, create_proxy_router
from airlock.store import JsonCaseStore


def _public_resolver(hostname):
    return ["93.184.216.34"]


def _sealed_case(tmp_path, *, auth_headers=None, search_schema=None):
    store = JsonCaseStore(tmp_path)
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["93.184.216.34"],
    )
    case = service.open_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        evidence_mode=EvidenceMode.TRANSCRIPT_ONLY,
        capabilities=ObservationCapabilities(
            mcp_traffic=True,
            tool_results=True,
            server_egress=False,
            server_filesystem=False,
        ),
    )
    case = service.record_inventory(
        case.case_id,
        declarations=[
            ToolDeclaration(
                name="search_docs",
                input_schema=search_schema or {},
                annotations={"readOnlyHint": True},
            ),
            ToolDeclaration(name="export_report", annotations={"readOnlyHint": True}),
        ],
        protocol_version="2026-07-28",
        auth_context_fingerprint=fingerprint_auth_context(auth_headers),
    )
    service.start_probing(case.case_id)
    for tool_name in ["search_docs", "export_report"]:
        store.append_probe(
            case.case_id,
            ProbeRecord(
                probe_id=f"probe_{tool_name}",
                tool=tool_name,
                kind="baseline",
                accepted=True,
            ),
        )
    probed = store.load_case(case.case_id)
    checks = detect_findings(
        declarations=probed.declared_tools,
        events=probed.events,
        probes=probed.probes,
        canaries={},
        scope=probed.declared_scope,
        capabilities=probed.observation_capabilities,
        evidence_mode=probed.evidence_mode,
    )
    service.record_checks(case.case_id, checks=checks)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    return store, sealed


def test_denied_tool_returns_mcp_error_without_reaching_upstream(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(500)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "export_report",
            },
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "export_report", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32001,
            "message": "Tool blocked by Airlock policy",
            "data": {"case_id": case.case_id, "tool": "export_report"},
        },
    }
    assert upstream_calls == []


@pytest.mark.parametrize(
    "payload",
    [
        [
            {
                "jsonrpc": "2.0",
                "id": 71,
                "method": "tools/call",
                "params": {"name": "export_report", "arguments": {}},
            }
        ],
        "not-an-object",
        42,
        None,
    ],
)
def test_non_object_json_rpc_request_is_rejected_before_upstream(tmp_path, payload):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(500)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32600
    assert upstream_calls == []


@pytest.mark.parametrize(
    "method",
    ["resources/read", "prompts/get", "custom/state-change"],
)
def test_non_tool_capability_methods_are_denied_before_upstream(
    tmp_path,
    method,
):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(500)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": method,
            },
            json={
                "jsonrpc": "2.0",
                "id": 73,
                "method": method,
                "params": {},
            },
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32011
    assert upstream_calls == []


@pytest.mark.parametrize("case_id", ["not-a-case", f"af_{'0' * 32}"])
def test_unknown_case_returns_bounded_error(case_id, tmp_path):
    store = JsonCaseStore(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(500)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            f"/cases/{case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 72, "method": "ping"},
        )

    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": -32000,
        "message": "Airlock case not found",
    }
    assert str(tmp_path) not in response.text
    assert upstream_calls == []


def test_approved_tool_is_forwarded_once_and_transcript_is_recorded(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "MCP-Session-Id": "legacy-session-1",
                "Set-Cookie": "suspect_session=poisoned",
            },
            json={
                "jsonrpc": "2.0",
                "id": 8,
                "result": {"content": [{"type": "text", "text": "Airlock docs"}]},
            },
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )
    payload = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "search_docs", "arguments": {"query": "airlock"}},
    }

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "search_docs",
            },
            json=payload,
        )

    assert response.status_code == 200
    assert response.json()["result"]["content"][0]["text"] == "Airlock docs"
    assert response.headers["mcp-session-id"] == "legacy-session-1"
    assert "set-cookie" not in response.headers
    assert len(upstream_calls) == 1
    assert str(upstream_calls[0].url) == "https://fixture.example/mcp"
    assert upstream_calls[0].headers["mcp-protocol-version"] == "2026-07-28"
    assert json.loads(upstream_calls[0].content) == payload


def test_runtime_transcript_retention_is_bounded(tmp_path):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        request_payload = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            json={
                "jsonrpc": "2.0",
                "id": request_payload["id"],
                "result": {"content": []},
            },
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
            max_runtime_events=2,
        )
    )

    with TestClient(app) as client:
        for request_id in (81, 82):
            response = client.post(
                f"/cases/{case.case_id}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": "search_docs", "arguments": {}},
                },
            )
            assert response.status_code == 200

    persisted = store.load_case(case.case_id)
    runtime_events = [
        event
        for event in persisted.events
        if event.probe_id.startswith("runtime_")
    ]
    assert len(runtime_events) == 2
    assert persisted.runtime_events_dropped == 2

    events = store.load_case(case.case_id).events
    assert [event.kind for event in events] == [
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
    ]
    assert all(event.tool == "search_docs" for event in events)
    assert "arguments" not in events[0].details
    assert events[0].details["arguments_digest"].startswith("sha256:")


def test_modern_routing_header_name_mismatch_is_rejected_before_upstream(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "search_docs",
            },
            json={
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "export_report", "arguments": {}},
            },
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020
    assert upstream_calls == []


def test_routing_header_mismatch_cannot_bypass_checks_by_omitting_version(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "Mcp-Method": "tools/call",
                "Mcp-Name": "export_report",
            },
            json={
                "jsonrpc": "2.0",
                "id": 91,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020
    assert upstream_calls == []


@pytest.mark.parametrize(
    "headers",
    [
        {"Mcp-Param-Tenant": "other-tenant"},
        {"Mcp-Param-Undeclared": "admin"},
    ],
)
def test_mcp_parameter_routing_headers_must_match_inventoried_schema_and_body(
    tmp_path,
    headers,
):
    store, case = _sealed_case(
        tmp_path,
        search_schema={
            "type": "object",
            "properties": {
                "tenant": {
                    "type": "string",
                    "x-mcp-header": "Tenant",
                }
            },
        },
    )
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "search_docs",
                **headers,
            },
            json={
                "jsonrpc": "2.0",
                "id": 95,
                "method": "tools/call",
                "params": {
                    "name": "search_docs",
                    "arguments": {"tenant": "audited-tenant"},
                },
            },
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020
    assert upstream_calls == []


def test_json_rpc_response_message_is_forwarded_without_tool_dispatch(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(202)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )
    payload = {"jsonrpc": "2.0", "id": 92, "result": {"accepted": True}}

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json=payload,
        )

    assert response.status_code == 202
    assert len(upstream_calls) == 1
    assert json.loads(upstream_calls[0].content) == payload


def test_public_gateway_fails_closed_until_case_is_sealed(tmp_path):
    store = JsonCaseStore(tmp_path)
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["93.184.216.34"],
    )
    case = service.open_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        evidence_mode=EvidenceMode.TRANSCRIPT_ONLY,
        capabilities=ObservationCapabilities(
            mcp_traffic=True,
            tool_results=True,
            server_egress=False,
            server_filesystem=False,
        ),
    )
    case = service.record_inventory(
        case.case_id,
        declarations=[ToolDeclaration(name="search_docs")],
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "search_docs",
            },
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32002
    assert upstream_calls == []


def test_modern_base64_sentinel_tool_name_is_decoded_before_comparison(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 11, "result": {"content": []}},
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "=?base64?c2VhcmNoX2RvY3M=?=",
            },
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert "result" in response.json()
    assert len(upstream_calls) == 1


def test_malformed_base64_sentinel_header_is_a_header_mismatch_error(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "=?base64?not-valid!?=",
            },
            json={
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020
    assert upstream_calls == []


def test_new_tool_advertised_after_seal_fails_closed(tmp_path):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 13,
                "result": {
                    "tools": [
                        {
                            "name": "new_unreviewed_tool",
                            "description": "Appeared after approval",
                            "inputSchema": {"type": "object"},
                            "annotations": {"readOnlyHint": True},
                        }
                    ]
                },
            },
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            json={"jsonrpc": "2.0", "id": 13, "method": "tools/list", "params": {}},
        )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32003
    failed_case = store.load_case(case.case_id)
    assert failed_case.enforcement_active is False
    assert failed_case.status.value == "incomplete"


def test_terminal_page_of_paginated_catalog_is_validated_as_a_page(tmp_path):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 14,
                "result": {
                    "tools": [
                        {
                            "name": "export_report",
                            "description": "",
                            "inputSchema": {},
                            "annotations": {"readOnlyHint": True},
                        }
                    ]
                },
            },
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/list",
                "params": {"cursor": "page-2"},
            },
        )

    assert response.status_code == 200
    assert response.json()["result"]["tools"][0]["name"] == "export_report"
    assert store.load_case(case.case_id).enforcement_active is True


@pytest.mark.parametrize("method", ["get", "delete"])
def test_public_gateway_fails_closed_for_legacy_methods_before_seal(tmp_path, method):
    store = JsonCaseStore(tmp_path)
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=_public_resolver,
    )
    case = service.open_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        evidence_mode=EvidenceMode.TRANSCRIPT_ONLY,
        capabilities=ObservationCapabilities(
            mcp_traffic=True,
            tool_results=True,
            server_egress=False,
            server_filesystem=False,
        ),
    )
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = getattr(client, method)(f"/cases/{case.case_id}/mcp")

    assert response.json()["error"]["code"] == -32002
    assert upstream_calls == []


def test_gateway_credentials_and_cookies_are_not_forwarded_to_target(tmp_path):
    target_headers = {"Authorization": "Bearer target-credential"}
    store, case = _sealed_case(tmp_path, auth_headers=target_headers)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 21, "result": {"content": []}},
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            upstream_headers=target_headers,
            credential_target_urls={"https://fixture.example/mcp"},
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            headers={
                "Authorization": "Bearer gateway-credential",
                "Cookie": "session=private",
                "X-Forwarded-For": "127.0.0.1",
                "X-Airlock-Probe-Id": "attacker-controlled",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "search_docs",
            },
            json={
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert len(upstream_calls) == 1
    headers = upstream_calls[0].headers
    assert headers["authorization"] == "Bearer target-credential"
    assert "cookie" not in headers
    assert "x-forwarded-for" not in headers
    assert "x-airlock-probe-id" not in headers
    assert all(
        event.probe_id != "attacker-controlled"
        for event in store.load_case(case.case_id).events
    )


def test_changed_target_auth_context_fails_closed_before_upstream(tmp_path):
    store, case = _sealed_case(
        tmp_path,
        auth_headers={"Authorization": "Bearer audited-token"},
    )
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            upstream_headers={"Authorization": "Bearer changed-token"},
            credential_target_urls={"https://fixture.example/mcp"},
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 94, "method": "ping", "params": {}},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32007
    assert upstream_calls == []
    failed_case = store.load_case(case.case_id)
    assert failed_case.status.value == "incomplete"
    assert failed_case.enforcement_active is False


@pytest.mark.parametrize("invalid_name", [None, 42])
def test_malformed_tool_call_name_is_rejected_before_upstream(tmp_path, invalid_name):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )
    params = {"arguments": {}}
    if invalid_name is not None:
        params["name"] = invalid_name

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": params,
            },
        )

    assert response.json()["error"]["code"] == -32602
    assert upstream_calls == []


def test_oversized_request_is_rejected_before_upstream(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
            max_request_bytes=128,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            content=b"x" * 129,
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert upstream_calls == []


def test_dns_binding_change_fails_closed_before_upstream(tmp_path):
    store, case = _sealed_case(tmp_path)
    upstream_calls = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request)
        return httpx.Response(200)

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=lambda hostname: ["93.184.216.35"],
        )
    )

    with TestClient(app) as client:
        response = client.get(f"/cases/{case.case_id}/mcp")

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32004
    assert upstream_calls == []
    assert store.load_case(case.case_id).status.value == "incomplete"


def test_tools_list_changed_notification_is_removed_and_disables_enforcement(
    tmp_path,
):
    store, case = _sealed_case(tmp_path)

    class EventStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"event: message\n"
            yield b'data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n\n'

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=EventStream(),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        with client.stream("GET", f"/cases/{case.case_id}/mcp") as response:
            body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "content-length" not in response.headers
    assert b"notifications/tools/list_changed" not in body
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert persisted.enforcement_active is False


def test_server_initiated_sampling_request_is_removed_from_sse(tmp_path):
    store, case = _sealed_case(tmp_path)

    class ServerRequestStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield (
                b'\xef\xbb\xbfdata: {"jsonrpc":"2.0","id":91,'
                b'"method":"sampling/createMessage","params":{}}\n\n'
            )
            yield (
                b"event: message\n"
                b'data: {"jsonrpc":"2.0",'
                b'"method":"notifications/progress",'
                b'"params":{"progressToken":"p1","progress":1}}\n\n'
            )

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=ServerRequestStream(),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        with client.stream("GET", f"/cases/{case.case_id}/mcp") as response:
            body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert b"sampling/createMessage" not in body
    assert b"notifications/progress" in body
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert persisted.enforcement_active is False


def test_json_server_initiated_request_is_rejected_and_disables_enforcement(
    tmp_path,
):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 92,
                "method": "elicitation/create",
                "params": {"message": "Send credentials"},
            },
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 41, "method": "ping"},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32012
    assert "Send credentials" not in response.text
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert persisted.enforcement_active is False


def test_tools_list_sse_cannot_smuggle_a_server_initiated_request(tmp_path):
    store, case = _sealed_case(tmp_path)
    matching_tools = [
        {
            "name": "search_docs",
            "description": "",
            "inputSchema": {},
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "export_report",
            "description": "",
            "inputSchema": {},
            "annotations": {"readOnlyHint": True},
        },
    ]
    result_message = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 44,
            "result": {"tools": matching_tools},
        },
        separators=(",", ":"),
    ).encode()

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=(
                b'\xef\xbb\xbfdata: {"jsonrpc":"2.0","id":93,'
                b'"method":"sampling/createMessage","params":{}}\n\n'
                + b"event: message\ndata: "
                + result_message
                + b"\n\n"
            ),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 44,
                "method": "tools/list",
                "params": {},
            },
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32012
    assert b"sampling/createMessage" not in response.content
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert persisted.enforcement_active is False


def test_matching_tools_list_sse_passes_catalog_validation(tmp_path):
    store, case = _sealed_case(tmp_path)
    result_message = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 45,
            "result": {
                "tools": [
                    {
                        "name": "search_docs",
                        "description": "",
                        "inputSchema": {},
                        "annotations": {"readOnlyHint": True},
                    },
                    {
                        "name": "export_report",
                        "description": "",
                        "inputSchema": {},
                        "annotations": {"readOnlyHint": True},
                    },
                ]
            },
        },
        separators=(",", ":"),
    ).encode()

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=b"event: message\ndata: " + result_message + b"\n\n",
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 45,
                "method": "tools/list",
                "params": {},
            },
        )

    assert response.status_code == 200
    assert b'"result"' in response.content
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "sealed_allowed"
    assert persisted.enforcement_active is True


def test_cr_only_and_mixed_sse_line_endings_are_forwarded(tmp_path):
    store, case = _sealed_case(tmp_path)
    first = (
        b'data: {"jsonrpc":"2.0","method":"notifications/progress",'
        b'"params":{"progressToken":"a","progress":1}}\r\r'
    )
    second = (
        b'data: {"jsonrpc":"2.0","method":"notifications/cancelled",'
        b'"params":{"requestId":1}}\n\r'
    )

    class MixedLineStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield first[:-1]
            yield first[-1:] + second

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=MixedLineStream(),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        with client.stream("GET", f"/cases/{case.case_id}/mcp") as response:
            body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert b"notifications/progress" in body
    assert b"notifications/cancelled" in body
    assert store.load_case(case.case_id).enforcement_active is True


def test_sse_rejection_callback_runs_before_the_next_forwarded_message():
    async def exercise_filter():
        callbacks: list[str] = []

        async def chunks():
            yield (
                b'data: {"jsonrpc":"2.0","id":1,'
                b'"method":"sampling/createMessage","params":{}}\n\n'
                b'data: {"jsonrpc":"2.0","method":"notifications/progress",'
                b'"params":{"progressToken":"p","progress":1}}\n\n'
            )

        state = {
            "raw_response_bytes": 0,
            "filtered_server_messages": 0,
            "bom_checked": 0,
        }
        iterator = _filter_sse_chunks(
            chunks(),
            state=state,
            max_raw_bytes=4096,
            on_filtered=lambda: callbacks.append("filtered"),
        )
        first_forwarded = await iterator.__anext__()
        return callbacks, first_forwarded

    callbacks, first_forwarded = asyncio.run(exercise_filter())

    assert callbacks == ["filtered"]
    assert b"notifications/progress" in first_forwarded


def test_encoded_runtime_response_is_rejected_before_forwarding(tmp_path):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
            content=gzip.compress(b"compressed-suspect-content"),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 42, "method": "ping"},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32013
    assert b"compressed-suspect-content" not in response.content
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"


def test_buffered_response_total_duration_limit_disables_enforcement(tmp_path):
    store, case = _sealed_case(tmp_path)

    class SlowJsonStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(0.05)
            yield b'{"jsonrpc":"2.0","id":43,"result":{}}'

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=SlowJsonStream(),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
            upstream_read_timeout_seconds=0.1,
            max_stream_duration_seconds=0.01,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 43, "method": "ping"},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32014
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert persisted.enforcement_active is False


def test_oversized_streamed_tool_result_disables_enforcement(tmp_path):
    store, case = _sealed_case(tmp_path)

    class OversizedEventStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"a" * 40
            yield b"b" * 40

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=OversizedEventStream(),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
            max_buffered_response_bytes=64,
        )
    )

    with TestClient(app) as client:
        with client.stream(
            "POST",
            f"/cases/{case.case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 83,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        ) as response:
            body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert len(body) <= 64
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert persisted.enforcement_active is False
    assert any(
        event.kind == EventKind.SENSOR_FAILURE
        and event.details.get("failure_class") == "stream_byte_limit"
        for event in persisted.events
    )


def test_tool_stream_duration_limit_disables_enforcement(tmp_path):
    store, case = _sealed_case(tmp_path)

    class SlowEventStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(0.05)
            yield b"late"

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=SlowEventStream(),
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
            upstream_read_timeout_seconds=0.1,
            max_stream_duration_seconds=0.01,
        )
    )

    with TestClient(app) as client:
        with client.stream(
            "POST",
            f"/cases/{case.case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 84,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        ) as response:
            body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert body == b""
    persisted = store.load_case(case.case_id)
    assert persisted.status.value == "incomplete"
    assert any(
        event.details.get("failure_class") == "stream_duration_limit"
        for event in persisted.events
    )


def test_oversized_buffered_upstream_response_fails_closed(tmp_path):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b"x" * 129,
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
            max_buffered_response_bytes=128,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 30, "method": "ping", "params": {}},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32005
    failed_case = store.load_case(case.case_id)
    assert failed_case.status.value == "incomplete"
    assert failed_case.enforcement_active is False


@pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
def test_upstream_redirect_fails_closed_without_exposing_location(
    tmp_path,
    status_code,
):
    store, case = _sealed_case(tmp_path)

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={"Location": "https://suspect.example/direct-mcp"},
        )

    upstream_transport = httpx.MockTransport(upstream_handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: upstream_transport,
            target_resolver=_public_resolver,
        )
    )

    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case.case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 93, "method": "ping", "params": {}},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32006
    assert "location" not in response.headers
    assert "suspect.example" not in response.text
    failed_case = store.load_case(case.case_id)
    assert failed_case.status.value == "incomplete"
    assert failed_case.enforcement_active is False


def _sealed_case_for_protocol_test(tmp_path, protocol_version="2026-07-28"):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
        target_binding=TargetBinding(
            scheme="https",
            hostname="fixture.example",
            port=443,
            resolved_ips=["93.184.216.34"],
        ),
    )
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=_public_resolver,
    )
    declarations = [ToolDeclaration(name="search_docs", annotations={"readOnlyHint": True})]
    service.record_inventory(
        case.case_id,
        declarations=declarations,
        protocol_version=protocol_version,
        auth_context_fingerprint=fingerprint_auth_context({}),
    )
    service.start_probing(case.case_id)
    store.append_probe(
        case.case_id,
        ProbeRecord(probe_id="p1", tool="search_docs", kind="baseline",
                    accepted=True, completed=True),
    )
    checks = detect_findings(
        declarations=declarations,
        events=[],
        probes=store.load_case(case.case_id).probes,
        canaries={},
        scope=DeclaredScope(),
        capabilities=ObservationCapabilities.controlled_fixture(),
        evidence_mode=EvidenceMode.CONTROLLED_FIXTURE,
    )
    service.record_checks(case.case_id, checks=checks)
    service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_ALL,
        approved_tools=["search_docs"],
        approval_required_tools=["search_docs"],
        decision_source="test",
    )
    return store, case.case_id


def _protocol_app(store, forwarded):
    def handler(request: httpx.Request) -> httpx.Response:
        forwarded.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    transport = httpx.MockTransport(handler)
    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=lambda binding: transport,
            target_resolver=_public_resolver,
        )
    )
    return app


def test_a_runtime_protocol_version_other_than_the_audited_one_is_recorded(tmp_path):
    # The harness pins its own client version and Airlock pins the one its
    # audit client negotiated, so these never match in practice. Refusing on
    # the difference made the proxy unusable with TrueForge, which initializes
    # at 2025-11-25 against an audit at 2026-07-28. The drift is recorded as
    # evidence instead; the catalog-change check is what enforces that the
    # audited surface has not moved.
    store, case_id = _sealed_case_for_protocol_test(tmp_path)
    forwarded = []
    with TestClient(_protocol_app(store, forwarded)) as client:
        response = client.post(
            f"/cases/{case_id}/mcp",
            headers={"mcp-protocol-version": "2025-11-25"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert len(forwarded) == 1
    drift = [
        event
        for event in store.load_case(case_id).events
        if event.kind is EventKind.PROTOCOL_VERSION_DRIFT
    ]
    assert len(drift) == 1
    assert drift[0].details["audited_protocol_version"] == "2026-07-28"
    assert drift[0].details["runtime_protocol_version"] == "2025-11-25"


def test_the_audited_protocol_version_is_forwarded(tmp_path):
    store, case_id = _sealed_case_for_protocol_test(tmp_path)
    forwarded = []
    with TestClient(_protocol_app(store, forwarded)) as client:
        response = client.post(
            f"/cases/{case_id}/mcp",
            headers={
                "mcp-protocol-version": "2026-07-28",
                "mcp-method": "tools/call",
                "mcp-name": "search_docs",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert len(forwarded) == 1


def test_initialize_is_not_refused_for_the_version_it_requests(tmp_path):
    # An initialize body carries the version the client is asking for, not the
    # one it settles on. Refusing on it breaks every real MCP handshake, which
    # is how this was found: a real client could not connect through the proxy.
    store, case_id = _sealed_case_for_protocol_test(tmp_path)
    forwarded = []
    with TestClient(_protocol_app(store, forwarded)) as client:
        response = client.post(
            f"/cases/{case_id}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )

    assert response.status_code == 200
    assert len(forwarded) == 1


def test_a_real_client_can_negotiate_with_server_discover(tmp_path):
    # Without server/discover in the allowed surface, no modern MCP client can
    # complete a handshake through the proxy.
    store, case_id = _sealed_case_for_protocol_test(tmp_path)
    forwarded = []
    with TestClient(_protocol_app(store, forwarded)) as client:
        response = client.post(
            f"/cases/{case_id}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
        )

    assert response.status_code == 200
    assert len(forwarded) == 1


def test_the_pinned_transport_cannot_be_replaced_by_an_injected_client(tmp_path):
    # Injection replaces the transport, which is built per request from the
    # binding this case validated. There is no parameter that substitutes the
    # whole client and so skips DNS pinning.
    import inspect

    from airlock import proxy as proxy_module

    signature = inspect.signature(create_proxy_router)
    assert "upstream_client" not in signature.parameters
    assert "upstream_transport_factory" in signature.parameters

    source = inspect.getsource(proxy_module)
    assert "transport=build_upstream_transport(binding)" in source


def test_the_transport_factory_receives_the_validated_binding(tmp_path):
    store, case_id = _sealed_case_for_protocol_test(tmp_path)
    seen_bindings = []

    def factory(binding):
        seen_bindings.append(binding)
        return httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "result": {}}
            )
        )

    app = FastAPI()
    app.include_router(
        create_proxy_router(
            store,
            upstream_transport_factory=factory,
            target_resolver=_public_resolver,
        )
    )
    with TestClient(app) as client:
        response = client.post(
            f"/cases/{case_id}/mcp",
            headers={
                "mcp-protocol-version": "2026-07-28",
                "mcp-method": "tools/call",
                "mcp-name": "search_docs",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {}},
            },
        )

    assert response.status_code == 200
    assert len(seen_bindings) == 1
    assert seen_bindings[0].hostname == "fixture.example"
    assert seen_bindings[0].resolved_ips == ["93.184.216.34"]
