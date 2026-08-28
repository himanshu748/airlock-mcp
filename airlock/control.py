from __future__ import annotations

import hashlib
import json
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from functools import wraps
from typing import Annotated, Any, Awaitable, ParamSpec, Protocol, TypeVar

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .audit import AuditExecutor
from .case_service import CaseService
from .models import (
    AIRLOCK_DISCLAIMER,
    CaseRecord,
    CaseStatus,
    DecisionChoice,
    DeclaredScope,
    EvidenceMode,
    ObservationCapabilities,
    ToolDeclaration,
)
from .policy import (
    CaseBlockedError,
    DecisionRequiredError,
    compile_connector_manifest,
    compile_policy,
)
from .store import JsonCaseStore


TargetResolver = Callable[[str], Iterable[str]]
_P = ParamSpec("_P")
_R = TypeVar("_R")


class AuditOperations(Protocol):
    async def inventory(self, case_id: str) -> CaseRecord: ...

    async def probe(
        self,
        case_id: str,
        *,
        tool_name: str,
        case_budget: int = 48,
        per_tool_cap: int = 12,
    ) -> CaseRecord: ...


_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
_REMOTE_STATEFUL = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=True,
)
_SENSITIVE_REMOTE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=True,
)
_SENSITIVE_STATEFUL = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)
_CONNECTOR_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_ANNOTATION_KEYS = {
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
}


def _anticipated_errors(
    function: Callable[_P, Awaitable[_R]],
) -> Callable[_P, Awaitable[_R]]:
    @wraps(function)
    async def guarded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        try:
            return await function(*args, **kwargs)
        except FileNotFoundError as exc:
            raise ToolError("case not found") from exc
        except (
            CaseBlockedError,
            DecisionRequiredError,
            ValueError,
        ) as exc:
            raise ToolError(str(exc)) from exc

    return guarded


def _system_resolver(hostname: str) -> list[str]:
    return sorted(
        {
            item[4][0]
            for item in socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        }
    )


def _transcript_capabilities() -> ObservationCapabilities:
    return ObservationCapabilities(
        mcp_traffic=True,
        tool_results=True,
        server_egress=False,
        server_filesystem=False,
    )


def _case_summary(case: CaseRecord) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "status": case.status.value,
        "evidence_mode": case.evidence_mode.value,
        "observation_capabilities": case.observation_capabilities.model_dump(
            mode="json"
        ),
        "proxy_url": case.proxy_url,
        "enforcement_active": case.enforcement_active,
        "probe_budget": case.probe_budget,
        "probes_run": case.probes_run,
        "runtime_events_dropped": case.runtime_events_dropped,
        "disclaimer": case.disclaimer,
    }


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _tool_id_maps(case: CaseRecord) -> tuple[dict[str, str], dict[str, str]]:
    name_to_id = {
        declaration.name: f"tool_{index:04d}"
        for index, declaration in enumerate(case.declared_tools, start=1)
    }
    return name_to_id, {tool_id: name for name, tool_id in name_to_id.items()}


def _safe_declaration(
    declaration: ToolDeclaration,
    *,
    tool_id: str,
) -> dict[str, Any]:
    canonical_schema = json.dumps(
        declaration.input_schema,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    annotations = {
        key: value
        for key, value in declaration.annotations.items()
        if key in _SAFE_ANNOTATION_KEYS and isinstance(value, bool)
    }
    return {
        "tool_id": tool_id,
        "annotations": annotations,
        "description_digest": _sha256(declaration.description.encode("utf-8")),
        "input_schema_digest": _sha256(canonical_schema),
    }


def _inventory_payload(case: CaseRecord) -> dict[str, Any]:
    name_to_id, _ = _tool_id_maps(case)
    return {
        **_case_summary(case),
        "protocol_version": case.protocol_version,
        "catalog_digest": case.catalog_digest,
        "declared_tools": [
            _safe_declaration(
                declaration,
                tool_id=name_to_id[declaration.name],
            )
            for declaration in case.declared_tools
        ],
        "raw_declarations_artifact": "airlock-report.json",
    }


def _evidence_payload(
    case: CaseRecord,
    *,
    include_observations: bool = False,
    observation_offset: int = 0,
    observation_limit: int = 50,
) -> dict[str, Any]:
    # Event details can contain untrusted tool output. The control MCP returns only
    # provenance metadata and detector findings so raw content does not re-enter
    # the model through read_evidence.
    name_to_id, _ = _tool_id_maps(case)

    def model_tool_id(tool_name: str) -> str:
        if tool_name == "__catalog__":
            return "catalog"
        return name_to_id.get(tool_name, "unmapped_tool")

    observations = [
        {
            "event_id": event.event_id,
            "probe_ref": _sha256(event.probe_id.encode("utf-8")),
            "tool_id": model_tool_id(event.tool),
            "kind": event.kind.value,
            "sensor": event.sensor,
            "observed_at": event.observed_at.isoformat(),
        }
        for event in case.events
    ]
    # The full event list grows with every probe and runtime call, and at the
    # default budget it alone exceeds what a model can take in one response.
    # Pass 4 needs the checks, not the per-event provenance, so the counts
    # travel by default and the detail is paged on request.
    summary: dict[str, Any] = {"by_kind": {}, "by_sensor": {}}
    for event in observations:
        summary["by_kind"][event["kind"]] = (
            summary["by_kind"].get(event["kind"], 0) + 1
        )
        summary["by_sensor"][event["sensor"]] = (
            summary["by_sensor"].get(event["sensor"], 0) + 1
        )
    return {
        **_case_summary(case),
        "checks": [
            {
                "tool_id": model_tool_id(finding.tool),
                "check": finding.check.value,
                "status": finding.status.value,
                "verdict": (
                    finding.verdict.value if finding.verdict is not None else None
                ),
                "evidence_strength": finding.evidence_strength.value,
                "sensor": finding.sensor,
                "evidence_refs": [
                    _sha256(reference.encode("utf-8"))
                    for reference in finding.evidence_refs
                ],
                "explanation_digest": _sha256(
                    finding.explanation.encode("utf-8")
                ),
            }
            for finding in case.checks
        ],
        "observation_summary": summary,
        "observation_count": len(observations),
        "observations": (
            observations[observation_offset : observation_offset + observation_limit]
            if include_observations
            else []
        ),
        "observations_returned": (
            len(observations[observation_offset : observation_offset + observation_limit])
            if include_observations
            else 0
        ),
        "observation_offset": observation_offset if include_observations else 0,
        "observations_omitted_note": (
            None
            if include_observations
            else (
                "Per-event provenance is omitted so the verdict fits in one "
                "response. Call read_evidence with include_observations=true "
                "to page through it."
            )
        ),
    }


def _validate_connector_name(connector_name: str) -> str:
    if not _CONNECTOR_NAME.fullmatch(connector_name):
        raise ValueError(
            "connector_name must contain only letters, numbers, dots, underscores "
            "or hyphens and must be at most 128 characters"
        )
    return connector_name


def create_control_server(
    *,
    store: JsonCaseStore,
    case_service: CaseService,
    audit_executor: AuditOperations | AuditExecutor,
    observation_capabilities_by_mode: Mapping[
        EvidenceMode, ObservationCapabilities
    ]
    | None = None,
    observation_target_urls_by_mode: Mapping[
        EvidenceMode, Iterable[str]
    ]
    | None = None,
    proxy_authorization: str | None = None,
) -> MCPServer:
    configured_capabilities = dict(
        observation_capabilities_by_mode
        if observation_capabilities_by_mode is not None
        else {EvidenceMode.TRANSCRIPT_ONLY: _transcript_capabilities()}
    )
    configured_targets = {
        mode: frozenset(urls)
        for mode, urls in (observation_target_urls_by_mode or {}).items()
    }
    server = MCPServer(
        "airlock-control",
        instructions=(
            "Audit submitted MCP servers, report only observed evidence and never "
            "state that a server is safe. Raw suspect tool results are quarantined."
        ),
    )

    @server.tool(
        name="open_case",
        description="Validate a target URL and create a persistent Airlock audit case.",
        annotations=_REMOTE_STATEFUL,
    )
    @_anticipated_errors
    async def open_case(
        target_url: str,
        evidence_mode: EvidenceMode = EvidenceMode.TRANSCRIPT_ONLY,
        declared_egress_hosts: list[str] | None = None,
        declared_filesystem_roots: list[str] | None = None,
    ) -> dict[str, Any]:
        capabilities = configured_capabilities.get(evidence_mode)
        if capabilities is None:
            raise ValueError(
                f"evidence mode {evidence_mode.value} is not configured on this "
                "Airlock deployment"
            )
        if evidence_mode != EvidenceMode.TRANSCRIPT_ONLY:
            registered_targets = configured_targets.get(evidence_mode, frozenset())
            if target_url not in registered_targets:
                raise ValueError(
                    f"target URL is not registered for {evidence_mode.value} "
                    "evidence"
                )
        case = case_service.open_case(
            target_url=target_url,
            declared_scope=DeclaredScope(
                egress_hosts=declared_egress_hosts or [],
                filesystem_roots=declared_filesystem_roots or [],
            ),
            evidence_mode=evidence_mode,
            capabilities=capabilities,
        )
        if case.target_binding is None:
            raise RuntimeError("case service did not persist a validated target binding")
        return {
            **_case_summary(case),
            "target_hostname": case.target_binding.hostname,
            "target_port": case.target_binding.port,
            "resolved_ips": case.target_binding.resolved_ips,
        }

    @server.tool(
        name="list_declared_tools",
        description=(
            "Inventory tools/list once, bind the case to that catalog and return "
            "opaque tool IDs, safe annotations and declaration digests."
        ),
        annotations=_REMOTE_STATEFUL,
    )
    @_anticipated_errors
    async def list_declared_tools(case_id: str) -> dict[str, Any]:
        case = store.load_case(case_id)
        if case.status == CaseStatus.CREATED:
            case = await audit_executor.inventory(case_id)
        return _inventory_payload(case)

    @server.tool(
        name="probe_tool",
        description=(
            "Exercise one inventoried opaque tool ID with a capped audit probe "
            "budget. The target can perform side effects."
        ),
        annotations=_SENSITIVE_REMOTE,
    )
    @_anticipated_errors
    async def probe_tool(
        case_id: str,
        tool_id: str,
        case_budget: Annotated[int, Field(ge=1, le=100)] = 48,
        per_tool_cap: Annotated[int, Field(ge=1, le=24)] = 12,
    ) -> dict[str, Any]:
        case = store.load_case(case_id)
        _, id_to_name = _tool_id_maps(case)
        tool_name = id_to_name.get(tool_id)
        if tool_name is None:
            raise ValueError("tool_id is not present in the inventoried catalog")
        if per_tool_cap > case_budget:
            raise ValueError("per_tool_cap cannot exceed case_budget")
        updated = await audit_executor.probe(
            case_id,
            tool_name=tool_name,
            case_budget=case_budget,
            per_tool_cap=per_tool_cap,
        )
        return {
            **_case_summary(updated),
            "tool_id": tool_id,
            "finding_count": len(updated.checks),
            "observation_count": len(updated.events),
        }

    @server.tool(
        name="read_evidence",
        description=(
            "Return detector findings and bounded observation provenance without raw "
            "suspect tool-result bodies."
        ),
        annotations=_READ_ONLY,
    )
    @_anticipated_errors
    async def read_evidence(
        case_id: str,
        include_observations: bool = False,
        observation_offset: Annotated[int, Field(ge=0)] = 0,
        observation_limit: Annotated[int, Field(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        return _evidence_payload(
            store.load_case(case_id),
            include_observations=include_observations,
            observation_offset=observation_offset,
            observation_limit=observation_limit,
        )

    @server.tool(
        name="seal_case",
        description=(
            "Record approved opaque tool IDs and activate fail-closed proxy "
            "enforcement. Configure the MCP client to require human approval for "
            "this tool."
        ),
        annotations=_SENSITIVE_STATEFUL,
    )
    @_anticipated_errors
    async def seal_case(
        case_id: str,
        choice: DecisionChoice,
        approved_tool_ids: list[str] | None = None,
        approval_required_tool_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        case = store.load_case(case_id)
        if case.audit_completed_at is None:
            raise ValueError("case must have a completed audit before it can be sealed")
        name_to_id, id_to_name = _tool_id_maps(case)

        def resolve_tool_ids(tool_ids: list[str]) -> list[str]:
            if len(set(tool_ids)) != len(tool_ids):
                raise ValueError("tool IDs must be unique")
            try:
                return [id_to_name[tool_id] for tool_id in tool_ids]
            except KeyError as exc:
                raise ValueError(
                    "tool ID is not present in the inventoried catalog"
                ) from exc

        sealed = case_service.seal_case(
            case_id,
            choice=choice,
            approved_tools=resolve_tool_ids(approved_tool_ids or []),
            approval_required_tools=resolve_tool_ids(
                approval_required_tool_ids or []
            ),
            decision_source="airlock_control_mcp_tool_call",
            decided_by="unattested_mcp_client_actor",
            human_approval_attested=False,
        )
        return {
            **_case_summary(sealed),
            "decision": (
                {
                    "choice": sealed.decision.choice.value,
                    "approved_tool_ids": [
                        name_to_id[name]
                        for name in sealed.decision.approved_tools
                    ],
                    "approval_required_tool_ids": [
                        name_to_id[name]
                        for name in sealed.decision.approval_required_tools
                    ],
                    "decision_source": sealed.decision.decision_source,
                    "decided_by": sealed.decision.decided_by,
                    "human_approval_attested": (
                        sealed.decision.human_approval_attested
                    ),
                    "decided_at": sealed.decision.decided_at.isoformat(),
                }
                if sealed.decision is not None
                else None
            ),
        }

    @server.tool(
        name="emit_policy",
        description=(
            "Compile and persist authenticated policy and connector artifacts for a "
            "sealed, allowed case. Configure the MCP client to require human "
            "approval for this tool."
        ),
        annotations=_SENSITIVE_STATEFUL,
    )
    @_anticipated_errors
    async def emit_policy(case_id: str, connector_name: str) -> dict[str, Any]:
        connector_name = _validate_connector_name(connector_name)
        case = store.load_case(case_id)
        policy = compile_policy(case, connector_name=connector_name)
        connector_manifest = compile_connector_manifest(
            case,
            connector_name=connector_name,
            expected_proxy_url=(
                f"{case_service.public_base_url}/cases/{case.case_id}/mcp"
            ),
            proxy_authorization=proxy_authorization,
        )
        policy_path = store.write_json_artifact(
            case_id,
            "airlock-policy.json",
            policy,
        )
        connector_path = store.write_json_artifact(
            case_id,
            "airlock-connector.json",
            connector_manifest,
        )
        return {
            "case_id": case_id,
            "policy_artifact": policy_path.name,
            "connector_artifact": connector_path.name,
            "policy_digest": _sha256(policy_path.read_bytes()),
            "connector_digest": _sha256(connector_path.read_bytes()),
            "disclaimer": AIRLOCK_DISCLAIMER,
        }

    return server


__all__ = ["create_control_server"]
