from __future__ import annotations

import asyncio
import hashlib
import json
import multiprocessing
import os
import select
import threading
import sys
import tempfile
from contextlib import asynccontextmanager
from collections import deque
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

import httpx2
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from .auth_context import ANONYMOUS_AUTH_CONTEXT, fingerprint_auth_context
from .bounded_transport import BoundedAuditTransport
from .canaries import (
    CanaryVault,
    CanaryVaultError,
    redact_canaries,
    redact_event_details,
)
from .case_service import CaseService
from .detectors import contains_injected_instruction, detect_findings
from .fixture_auth import fixture_probe_signature
from .models import (
    CaseRecord,
    CaseStatus,
    CheckName,
    EvidenceEvent,
    EventKind,
    ProbeRecord,
    StdioTarget,
    TargetBinding,
    ToolDeclaration,
)
from .pinned_transport import create_pinned_httpx2_transport
from .probes import PlannedProbe, ProbePlanner, ProbePlanningError
from .store import CaseIntegrityError


_EXPECTED_CANARY_LABELS = ("document_secret",)


# A teardown that starts after the audit deadline still has to be bounded,
# or a stalled shutdown hangs the caller instead of the audit.
_TEARDOWN_GRACE_SECONDS = 5.0


class StdioLaunchError(RuntimeError):
    """A stdio server failed, carrying the tail of what it printed to stderr."""

    def __init__(self, stdio_target: StdioTarget, stderr_tail: str) -> None:
        detail = f": {stderr_tail}" if stderr_tail else ""
        super().__init__(
            f"stdio target {stdio_target.name} failed{detail}"
        )
        self.stdio_target = stdio_target
        self.stderr_tail = stderr_tail


class AuditExecutor:
    def __init__(
        self,
        case_service: CaseService,
        *,
        canary_vault: CanaryVault | None = None,
        target_headers: Mapping[str, str] | None = None,
        fixture_signing_key: str | bytes | None = None,
        max_inventory_pages: int = 64,
        max_inventory_tools: int = 512,
        max_catalog_bytes: int = 2 * 1024 * 1024,
        max_audit_response_bytes: int = 4 * 1024 * 1024,
        audit_operation_timeout_seconds: float = 60.0,
        audit_total_timeout_seconds: float = 240.0,
        probe_planning_timeout_seconds: float = 5.0,
        probe_planning_memory_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        inventory_limits = {
            "max_inventory_pages": max_inventory_pages,
            "max_inventory_tools": max_inventory_tools,
            "max_catalog_bytes": max_catalog_bytes,
            "max_audit_response_bytes": max_audit_response_bytes,
            "probe_planning_memory_bytes": probe_planning_memory_bytes,
        }
        for name, value in inventory_limits.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in {
            "audit_operation_timeout_seconds": audit_operation_timeout_seconds,
            "audit_total_timeout_seconds": audit_total_timeout_seconds,
            "probe_planning_timeout_seconds": probe_planning_timeout_seconds,
        }.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive number")
        self.case_service = case_service
        self.canary_vault = canary_vault or CanaryVault(case_service.store)
        self.target_headers = dict(target_headers or {})
        if self.target_headers and not case_service.credential_target_urls:
            raise ValueError(
                "target headers require at least one exact credential target URL"
            )
        self.auth_context_fingerprint = fingerprint_auth_context(
            self.target_headers
        )
        self.fixture_signing_key = fixture_signing_key
        self.max_inventory_pages = max_inventory_pages
        self.max_inventory_tools = max_inventory_tools
        self.max_catalog_bytes = max_catalog_bytes
        self.max_audit_response_bytes = max_audit_response_bytes
        self.audit_operation_timeout_seconds = float(
            audit_operation_timeout_seconds
        )
        self.audit_total_timeout_seconds = float(audit_total_timeout_seconds)
        self.probe_planning_timeout_seconds = float(
            probe_planning_timeout_seconds
        )
        self.probe_planning_memory_bytes = probe_planning_memory_bytes

    async def inventory(
        self,
        case_id: str,
        *,
        target: Any = None,
        auth_context_fingerprint: str | None = None,
        deadline: float | None = None,
    ) -> CaseRecord:
        case = self.case_service.store.load_case(case_id)
        if target is None:
            self.case_service.revalidate_target(case_id)
        target_reference = target if target is not None else case.target_url
        declarations: list[ToolDeclaration] = []
        seen_cursors: set[str] = set()
        seen_tool_names: set[str] = set()
        pages_read = 0
        serialized_catalog_bytes = 0

        try:
            inventory_deadline = _earliest_deadline(
                asyncio.get_running_loop().time()
                + self.audit_operation_timeout_seconds,
                deadline,
            )
            async with _open_client_with_timeout(
                target_reference,
                binding=case.target_binding if target is None else None,
                stdio_target=case.stdio_target if target is None else None,
                headers=self.target_headers if target is None else None,
                max_response_bytes=self.max_audit_response_bytes,
                deadline=inventory_deadline,
                timeout_seconds=_remaining_operation_seconds(
                    inventory_deadline
                ),
            ) as client:
                cursor: str | None = None
                while True:
                    pages_read += 1
                    if pages_read > self.max_inventory_pages:
                        raise ValueError("tool inventory page limit exceeded")
                    page = await asyncio.wait_for(
                        client.list_tools(cursor=cursor),
                        timeout=_remaining_operation_seconds(
                            inventory_deadline
                        ),
                    )
                    for tool in page.tools:
                        annotations = (
                            tool.annotations.model_dump(
                                by_alias=True,
                                exclude_none=True,
                            )
                            if tool.annotations is not None
                            else {}
                        )
                        declaration = ToolDeclaration(
                            name=tool.name,
                            description=tool.description or "",
                            input_schema=tool.input_schema,
                            annotations=annotations,
                        )
                        if declaration.name in seen_tool_names:
                            raise ValueError(
                                "tool inventory contains a duplicate tool name"
                            )
                        seen_tool_names.add(declaration.name)
                        declarations.append(declaration)
                        if len(declarations) > self.max_inventory_tools:
                            raise ValueError("tool inventory tool limit exceeded")
                        serialized_catalog_bytes += len(
                            declaration.model_dump_json().encode("utf-8")
                        )
                        if serialized_catalog_bytes > self.max_catalog_bytes:
                            raise ValueError(
                                "tool inventory serialized size limit exceeded"
                            )
                    if page.next_cursor is None:
                        break
                    next_cursor = page.next_cursor
                    if not isinstance(next_cursor, str) or not next_cursor:
                        raise ValueError("tool inventory returned an invalid cursor")
                    if next_cursor in seen_cursors:
                        raise ValueError(
                            "tool inventory pagination cursor cycle detected"
                        )
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
                protocol_version = client.protocol_version

            return self.case_service.record_inventory(
                case_id,
                declarations=declarations,
                protocol_version=protocol_version,
                auth_context_fingerprint=(
                    auth_context_fingerprint
                    or (
                        self.auth_context_fingerprint
                        if target is None
                        else ANONYMOUS_AUTH_CONTEXT
                    )
                ),
            )
        except Exception:
            return self._record_inventory_failure(case_id)

    async def run(
        self,
        case_id: str,
        *,
        target: Any = None,
        observer: Any = None,
        case_budget: int = 48,
        per_tool_cap: int = 12,
        auth_context_fingerprint: str | None = None,
    ) -> CaseRecord:
        audit_deadline = (
            asyncio.get_running_loop().time() + self.audit_total_timeout_seconds
        )
        case = await self.inventory(
            case_id,
            target=target,
            auth_context_fingerprint=auth_context_fingerprint,
            deadline=audit_deadline,
        )
        if case.status != CaseStatus.INVENTORIED:
            return case
        self.case_service.start_probing(case_id)
        case = self.case_service.configure_probe_budget(
            case_id,
            probe_budget=case_budget,
        )
        try:
            canaries = self._load_or_plant_canaries(case_id)
        except (CanaryVaultError, CaseIntegrityError):
            return self._record_canary_failure(case_id)
        target_reference = target if target is not None else case.target_url
        if target is None:
            self.case_service.revalidate_target(case_id)
        observer_offset = len(observer.events) if observer is not None else 0

        try:
            async with _open_client_with_timeout(
                target_reference,
                binding=case.target_binding if target is None else None,
                stdio_target=case.stdio_target if target is None else None,
                headers=self.target_headers if target is None else None,
                max_response_bytes=self.max_audit_response_bytes,
                deadline=audit_deadline,
                timeout_seconds=self._call_timeout(audit_deadline),
            ) as client:
                for declaration in case.declared_tools:
                    _remaining_operation_seconds(audit_deadline)
                    current = self.case_service.store.load_case(case_id)
                    remaining = max(0, current.probe_budget - current.probes_run)
                    if remaining == 0:
                        break
                    existing_ids = {probe.probe_id for probe in current.probes}
                    existing_for_tool = sum(
                        probe.tool == declaration.name for probe in current.probes
                    )
                    tool_remaining = max(0, per_tool_cap - existing_for_tool)
                    if tool_remaining == 0:
                        continue
                    try:
                        candidates = await _plan_probes_with_deadline(
                            declaration,
                            canary=next(iter(canaries.values()), None),
                            case_budget=per_tool_cap,
                            per_tool_cap=per_tool_cap,
                            timeout_seconds=self._planning_timeout(audit_deadline),
                            memory_bytes=self.probe_planning_memory_bytes,
                        )
                    except ProbePlanningError:
                        return self._record_planning_failure(
                            case_id,
                            tool_name=declaration.name,
                            canaries=canaries,
                        )
                    planned = [
                        probe
                        for probe in candidates
                        if probe.probe_id not in existing_ids
                    ][: min(remaining, tool_remaining)]
                    for probe in planned:
                        observer_offset = await self._execute_probe(
                            case_id,
                            client=client,
                            probe=probe,
                            canaries=canaries,
                            observer=observer,
                            observer_offset=observer_offset,
                            deadline=audit_deadline,
                        )
        except Exception:
            return self._record_transport_failure(
                case_id,
                tool_names=[item.name for item in case.declared_tools],
                canaries=canaries,
            )

        return self._finish_if_covered(case_id, canaries=canaries)

    async def probe(
        self,
        case_id: str,
        *,
        tool_name: str,
        target: Any = None,
        observer: Any = None,
        case_budget: int = 48,
        per_tool_cap: int = 12,
    ) -> CaseRecord:
        audit_deadline = (
            asyncio.get_running_loop().time() + self.audit_total_timeout_seconds
        )
        case = self.case_service.store.load_case(case_id)
        if case.status == CaseStatus.CREATED:
            case = await self.inventory(
                case_id,
                target=target,
                deadline=audit_deadline,
            )
        if case.status != CaseStatus.INVENTORIED and case.status != CaseStatus.PROBING:
            return case
        declaration = next(
            (item for item in case.declared_tools if item.name == tool_name),
            None,
        )
        if declaration is None:
            raise ValueError("tool is not present in the inventoried catalog")
        if case.status != CaseStatus.PROBING:
            self.case_service.start_probing(case_id)
        case = self.case_service.configure_probe_budget(
            case_id,
            probe_budget=case_budget,
        )
        try:
            canaries = self._load_or_plant_canaries(case_id)
        except (CanaryVaultError, CaseIntegrityError):
            return self._record_canary_failure(case_id)
        remaining = max(0, case.probe_budget - case.probes_run)
        existing_ids = {probe.probe_id for probe in case.probes}
        existing_for_tool = sum(
            probe.tool == declaration.name for probe in case.probes
        )
        tool_remaining = max(0, per_tool_cap - existing_for_tool)
        try:
            candidates = await _plan_probes_with_deadline(
                declaration,
                canary=next(iter(canaries.values()), None),
                case_budget=per_tool_cap,
                per_tool_cap=per_tool_cap,
                timeout_seconds=self._planning_timeout(audit_deadline),
                memory_bytes=self.probe_planning_memory_bytes,
            )
        except ProbePlanningError:
            return self._record_planning_failure(
                case_id,
                tool_name=declaration.name,
                canaries=canaries,
            )
        planned = [
            item for item in candidates if item.probe_id not in existing_ids
        ][: min(remaining, tool_remaining)]
        target_reference = target if target is not None else case.target_url
        if target is None:
            self.case_service.revalidate_target(case_id)
        observer_offset = len(observer.events) if observer is not None else 0
        try:
            async with _open_client_with_timeout(
                target_reference,
                binding=case.target_binding if target is None else None,
                stdio_target=case.stdio_target if target is None else None,
                headers=self.target_headers if target is None else None,
                max_response_bytes=self.max_audit_response_bytes,
                deadline=audit_deadline,
                timeout_seconds=self._call_timeout(audit_deadline),
            ) as client:
                for item in planned:
                    observer_offset = await self._execute_probe(
                        case_id,
                        client=client,
                        probe=item,
                        canaries=canaries,
                        observer=observer,
                        observer_offset=observer_offset,
                        deadline=audit_deadline,
                    )
        except Exception:
            return self._record_transport_failure(
                case_id,
                tool_names=[tool_name],
                canaries=canaries,
            )
        return self._finish_if_covered(case_id, canaries=canaries)

    def _finish_if_covered(
        self,
        case_id: str,
        *,
        canaries: dict[str, str],
    ) -> CaseRecord:
        current = self.case_service.store.load_case(case_id)
        declared_names = {item.name for item in current.declared_tools}
        attempted_names = {
            item.tool for item in current.probes if item.completed
        }
        successful_names = {
            item.tool
            for item in current.probes
            if item.completed and item.accepted
        }
        if declared_names <= successful_names:
            return self._finalize(case_id, canaries=canaries)
        checks = self._detect(current, canaries=canaries)
        exhausted = (
            current.probe_budget > 0
            and current.probes_run >= current.probe_budget
        )
        status = (
            CaseStatus.INCOMPLETE
            if declared_names <= attempted_names or exhausted
            else CaseStatus.PROBING
        )
        partial = current.model_copy(
            update={"checks": checks, "status": status}
        )
        self.case_service.store.save_case(partial)
        return partial

    def _planning_timeout(self, deadline: float | None) -> float:
        """Clamp probe planning to the smaller of its own budget and the audit's."""
        if deadline is None:
            return self.probe_planning_timeout_seconds
        return min(
            self.probe_planning_timeout_seconds,
            _remaining_operation_seconds(deadline),
        )

    def _call_timeout(self, deadline: float | None) -> float:
        """Clamp a single call to the smaller of the per-call and audit budgets."""
        if deadline is None:
            return self.audit_operation_timeout_seconds
        return min(
            self.audit_operation_timeout_seconds,
            _remaining_operation_seconds(deadline),
        )

    async def _execute_probe(
        self,
        case_id: str,
        *,
        client: Client,
        probe: PlannedProbe,
        canaries: dict[str, str],
        observer: Any,
        observer_offset: int,
        deadline: float | None = None,
    ) -> int:
        arguments_digest = _digest(probe.arguments)
        supplied_ids = [
            label
            for label, value in canaries.items()
            if probe.supplied_canary == value
        ]
        reservation = ProbeRecord(
            probe_id=probe.probe_id,
            tool=probe.tool,
            kind=probe.kind,
            request=redact_canaries(probe.arguments, canaries),
            accepted=False,
            completed=False,
            supplied_canary_ids=supplied_ids,
        )
        if not self.case_service.store.reserve_probe(case_id, reservation):
            return observer_offset
        self.case_service.store.append_event(
            case_id,
            EvidenceEvent(
                event_id=f"ev_{uuid4().hex}",
                probe_id=probe.probe_id,
                tool=probe.tool,
                kind=EventKind.TOOL_CALL,
                sensor="mcp_transcript",
                details={"arguments_digest": arguments_digest},
            ),
        )

        accepted = False
        response_observed = False
        response_digest: str | None = None
        result_features: dict[str, Any]
        operation_timed_out = False
        try:
            metadata = {
                "io.airlock/caseId": case_id,
                "io.airlock/probeId": probe.probe_id,
            }
            case = self.case_service.store.load_case(case_id)
            if (
                self.fixture_signing_key is not None
                and case.evidence_mode.value == "controlled_fixture"
            ):
                metadata["io.airlock/sensorSignature"] = (
                    fixture_probe_signature(
                        self.fixture_signing_key,
                        case_id=case_id,
                        probe_id=probe.probe_id,
                        tool=probe.tool,
                    )
                )
            result = await asyncio.wait_for(
                client.call_tool(
                    probe.tool,
                    probe.arguments,
                    meta=metadata,
                ),
                timeout=self._call_timeout(deadline),
            )
            raw_result = result.model_dump(mode="json", by_alias=True)
            response_digest = _digest(raw_result)
            response_observed = True
            accepted = not result.is_error
            serialized_result = json.dumps(raw_result, sort_keys=True, default=str)
            result_features = {
                "response_digest": response_digest,
                "is_error": result.is_error,
                "content_types": sorted(
                    {
                        str(block.get("type", "unknown"))
                        for block in raw_result.get("content", [])
                        if isinstance(block, dict)
                    }
                ),
                "matched_canary_ids": sorted(
                    label
                    for label, value in canaries.items()
                    if value in serialized_result
                ),
                "injected_instruction_detected": contains_injected_instruction(
                    raw_result
                ),
            }
        except Exception as exc:
            operation_timed_out = isinstance(exc, asyncio.TimeoutError)
            failure_class = (
                "operation_timeout"
                if operation_timed_out
                else "transport_or_protocol"
            )
            response_digest = _digest(
                {"error_type": type(exc).__name__, "error": str(exc)}
            )
            result_features = {
                "response_digest": response_digest,
                "is_error": True,
                "error_type": type(exc).__name__,
                "content_types": [],
                "matched_canary_ids": [],
                "injected_instruction_detected": False,
            }

        self.case_service.store.complete_probe(
            case_id,
            ProbeRecord(
                probe_id=probe.probe_id,
                tool=probe.tool,
                kind=probe.kind,
                request=redact_canaries(probe.arguments, canaries),
                accepted=accepted,
                completed=True,
                response_digest=response_digest,
                supplied_canary_ids=supplied_ids,
            ),
        )
        self.case_service.store.append_event(
            case_id,
            EvidenceEvent(
                event_id=f"ev_{uuid4().hex}",
                probe_id=probe.probe_id,
                tool=probe.tool,
                kind=(
                    EventKind.TOOL_RESULT
                    if response_observed
                    else EventKind.SENSOR_FAILURE
                ),
                sensor="mcp_transcript",
                details=(
                    result_features
                    if response_observed
                    else {
                        "checks": [check.value for check in CheckName],
                        "failure_class": failure_class,
                        "response_digest": response_digest,
                    }
                ),
            ),
        )

        if observer is not None:
            new_events = observer.events[observer_offset:]
            for event in new_events:
                sanitized = event.model_copy(
                    update={"details": redact_event_details(event.details, canaries)}
                )
                self.case_service.store.append_event(case_id, sanitized)
            observer_offset = len(observer.events)
        if operation_timed_out:
            raise asyncio.TimeoutError
        return observer_offset

    def _load_or_plant_canaries(self, case_id: str) -> dict[str, str]:
        try:
            return self.canary_vault.load(
                case_id,
                expected_labels=_EXPECTED_CANARY_LABELS,
            )
        except FileNotFoundError:
            return self.canary_vault.plant(
                case_id,
                labels=list(_EXPECTED_CANARY_LABELS),
            )

    def _record_canary_failure(self, case_id: str) -> CaseRecord:
        current = self.case_service.store.load_case(case_id)
        for declaration in current.declared_tools:
            self.case_service.store.append_event(
                case_id,
                EvidenceEvent(
                    event_id=f"ev_{uuid4().hex}",
                    probe_id=f"canary_{uuid4().hex}",
                    tool=declaration.name,
                    kind=EventKind.SENSOR_FAILURE,
                    sensor="canary_vault",
                    details={
                        "checks": [CheckName.CANARY_EXFILTRATION.value],
                        "failure_class": "canary_state_unavailable",
                    },
                ),
            )
        current = self.case_service.store.load_case(case_id)
        checks = self._detect(current, canaries={})
        return self.case_service.store.mark_incomplete(
            case_id,
            checks=checks,
        )

    def _record_inventory_failure(self, case_id: str) -> CaseRecord:
        self.case_service.store.append_event(
            case_id,
            EvidenceEvent(
                event_id=f"ev_{uuid4().hex}",
                probe_id=f"inventory_{uuid4().hex}",
                tool="__catalog__",
                kind=EventKind.SENSOR_FAILURE,
                sensor="mcp_inventory",
                details={
                    "checks": [],
                    "failure_class": "transport_protocol_or_bound",
                },
            ),
        )
        return self.case_service.store.mark_incomplete(case_id)

    def _record_transport_failure(
        self,
        case_id: str,
        *,
        tool_names: list[str],
        canaries: dict[str, str],
    ) -> CaseRecord:
        for tool_name in tool_names:
            self.case_service.store.append_event(
                case_id,
                EvidenceEvent(
                    event_id=f"ev_{uuid4().hex}",
                    probe_id=f"transport_{uuid4().hex}",
                    tool=tool_name,
                    kind=EventKind.SENSOR_FAILURE,
                    sensor="audit_transport",
                    details={
                        "checks": [check.value for check in CheckName],
                        "failure_class": "transport_protocol_or_bound",
                    },
                ),
            )
        current = self.case_service.store.load_case(case_id)
        checks = self._detect(current, canaries=canaries)
        return self.case_service.store.mark_incomplete(
            case_id,
            checks=checks,
        )

    def _record_planning_failure(
        self,
        case_id: str,
        *,
        tool_name: str,
        canaries: dict[str, str],
    ) -> CaseRecord:
        self.case_service.store.append_event(
            case_id,
            EvidenceEvent(
                event_id=f"ev_{uuid4().hex}",
                probe_id=f"planning_{uuid4().hex}",
                tool=tool_name,
                kind=EventKind.SENSOR_FAILURE,
                sensor="probe_planner",
                details={
                    "checks": [check.value for check in CheckName],
                    "failure_class": "schema_outside_bounded_profile",
                },
            ),
        )
        current = self.case_service.store.load_case(case_id)
        checks = self._detect(current, canaries=canaries)
        return self.case_service.store.mark_incomplete(
            case_id,
            checks=checks,
        )

    def _finalize(self, case_id: str, *, canaries: dict[str, str]) -> CaseRecord:
        case = self.case_service.store.load_case(case_id)
        checks = self._detect(case, canaries=canaries)
        return self.case_service.record_checks(case_id, checks=checks)

    @staticmethod
    def _detect(case: CaseRecord, *, canaries: dict[str, str]):
        return detect_findings(
            declarations=case.declared_tools,
            events=case.events,
            probes=case.probes,
            canaries=canaries,
            scope=case.declared_scope,
            capabilities=case.observation_capabilities,
            evidence_mode=case.evidence_mode,
        )


def _probe_planning_worker(
    sender,
    *,
    declaration_payload: dict[str, Any],
    canary: str | None,
    case_budget: int,
    per_tool_cap: int,
    memory_bytes: int,
) -> None:
    try:
        if sys.platform.startswith("linux"):
            import resource

            current_soft, current_hard = resource.getrlimit(resource.RLIMIT_AS)
            soft_limit = (
                memory_bytes
                if current_soft == resource.RLIM_INFINITY
                else min(memory_bytes, current_soft)
            )
            resource.setrlimit(
                resource.RLIMIT_AS,
                (soft_limit, current_hard),
            )
        declaration = ToolDeclaration.model_validate(declaration_payload)
        probes = ProbePlanner(
            case_budget=case_budget,
            per_tool_cap=per_tool_cap,
        ).plan(declaration, canary=canary)
        sender.send(("ok", probes))
    except BaseException:
        sender.send(("error", None))
    finally:
        sender.close()


def _terminate_planning_process(process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=1.0)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
    process.join(timeout=1.0)


def _plan_probes_in_process(
    declaration: ToolDeclaration,
    *,
    canary: str | None,
    case_budget: int,
    per_tool_cap: int,
    timeout_seconds: float,
    memory_bytes: int,
) -> tuple[PlannedProbe, ...]:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_probe_planning_worker,
        kwargs={
            "sender": sender,
            "declaration_payload": declaration.model_dump(mode="python"),
            "canary": canary,
            "case_budget": case_budget,
            "per_tool_cap": per_tool_cap,
            "memory_bytes": memory_bytes,
        },
        name="airlock-probe-planner",
        daemon=True,
    )
    started = False
    try:
        process.start()
        started = True
        sender.close()
        if not receiver.poll(timeout_seconds):
            raise ProbePlanningError("probe planning exceeded its deadline")
        try:
            status, payload = receiver.recv()
        except EOFError as exc:
            raise ProbePlanningError("probe planning worker exited early") from exc
        if status != "ok" or not isinstance(payload, tuple):
            raise ProbePlanningError("probe planning worker rejected the schema")
        if not all(isinstance(item, PlannedProbe) for item in payload):
            raise ProbePlanningError("probe planning worker returned invalid data")
        return payload
    finally:
        receiver.close()
        sender.close()
        if started:
            _terminate_planning_process(process)


async def _plan_probes_with_deadline(
    declaration: ToolDeclaration,
    *,
    canary: str | None,
    case_budget: int,
    per_tool_cap: int,
    timeout_seconds: float,
    memory_bytes: int,
) -> tuple[PlannedProbe, ...]:
    return await asyncio.to_thread(
        _plan_probes_in_process,
        declaration,
        canary=canary,
        case_budget=case_budget,
        per_tool_cap=per_tool_cap,
        timeout_seconds=timeout_seconds,
        memory_bytes=memory_bytes,
    )


def _digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _earliest_deadline(*deadlines: float | None) -> float:
    present = [value for value in deadlines if value is not None]
    return min(present)


def _remaining_operation_seconds(deadline: float) -> float:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise asyncio.TimeoutError
    return remaining


@asynccontextmanager
async def _open_client_with_timeout(
    target: Any,
    *,
    timeout_seconds: float,
    deadline: float | None = None,
    binding: TargetBinding | None = None,
    stdio_target: StdioTarget | None = None,
    headers: Mapping[str, str] | None = None,
    max_response_bytes: int = 4 * 1024 * 1024,
):
    """Open a client, bounding both setup and teardown by the audit deadline.

    Teardown recomputes what is left rather than reusing the value captured at
    open time, so a stalled shutdown cannot extend the audit past its bound.
    """

    def budget() -> float:
        if deadline is None:
            return timeout_seconds
        return min(timeout_seconds, _remaining_operation_seconds(deadline))

    manager = _open_client(
        target,
        binding=binding,
        stdio_target=stdio_target,
        headers=headers,
        max_response_bytes=max_response_bytes,
    )
    client = await asyncio.wait_for(manager.__aenter__(), timeout=budget())
    try:
        yield client
    finally:
        try:
            teardown_budget = budget()
        except asyncio.TimeoutError:
            # The audit is already over its bound. Still bound the teardown so
            # a stalled shutdown cannot hang the caller.
            teardown_budget = _TEARDOWN_GRACE_SECONDS
        await asyncio.wait_for(
            manager.__aexit__(None, None, None),
            timeout=teardown_budget,
        )


# The SDK merges the supplied env over get_default_environment(), which
# inherits HOME, LOGNAME, PATH, SHELL, TERM and USER from the host. Naming
# every one of them makes the child's environment ours rather than whatever
# the SDK decided to pass through.
_STDIO_INHERITED_ENV_VARS = ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER")
_STDIO_STDERR_CAPTURE_BYTES = 8 * 1024
# Teardown budget for the stderr drain, applied twice at most.
_STDIO_DRAIN_GRACE_SECONDS = 0.5
# Windows select() handles sockets only, so a pipe descriptor cannot be polled
# for readiness there and the drain falls back to blocking reads.
_CAN_POLL_PIPES = os.name != "nt"


def _stdio_child_environment(workdir: str) -> dict[str, str]:
    environment = {
        name: "" for name in _STDIO_INHERITED_ENV_VARS
    }
    environment.update(
        {
            # os.defpath is the platform's own fallback, so a Windows host
            # does not inherit a POSIX search path that resolves nothing.
            "PATH": os.environ.get("PATH") or os.defpath,
            "HOME": workdir,
            "TMPDIR": workdir,
            # Windows reads these rather than HOME and TMPDIR.
            "USERPROFILE": workdir,
            "TEMP": workdir,
            "TMP": workdir,
        }
    )
    return environment


class _BoundedStderr:
    """Drains a child's stderr, keeping only the last bytes.

    The SDK hands errlog straight to the subprocess as its stderr, so it has
    to be a real file descriptor. Writing that to a file would let a chatty or
    hostile server fill the disk, and never reading the pipe would let it block
    once the buffer filled.

    The drain stops on a flag rather than on end of file. A server that spawns
    a descendant holding the same stderr never closes the pipe, so waiting for
    EOF would leak this thread and its descriptor for the life of the process.
    """

    def __init__(self, limit: int = _STDIO_STDERR_CAPTURE_BYTES) -> None:
        self._limit = limit
        self._chunks: deque[bytes] = deque()
        self._size = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._read_fd, self._write_fd = os.pipe()
        if _CAN_POLL_PIPES:
            os.set_blocking(self._read_fd, False)
        self._writer = os.fdopen(self._write_fd, "wb", buffering=0)
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        try:
            while not self._stop.is_set():
                if _CAN_POLL_PIPES:
                    ready, _, _ = select.select([self._read_fd], [], [], 0.1)
                    if not ready:
                        continue
                try:
                    chunk = os.read(self._read_fd, 4096)
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                with self._lock:
                    self._chunks.append(chunk)
                    self._size += len(chunk)
                    while self._size > self._limit and len(self._chunks) > 1:
                        self._size -= len(self._chunks.popleft())
        finally:
            try:
                os.close(self._read_fd)
            except OSError:
                pass

    @property
    def stream(self) -> Any:
        return self._writer

    def tail(self) -> str:
        with self._lock:
            captured = b"".join(self._chunks)
        return captured[-self._limit :].decode("utf-8", "replace").strip()

    def close(self) -> None:
        # Close the writer first so the pipe can reach end of file, then give
        # the drain a moment to take what is still buffered. Setting the flag
        # straight away would discard exactly the tail worth keeping.
        try:
            self._writer.close()
        except OSError:
            pass
        self._thread.join(timeout=_STDIO_DRAIN_GRACE_SECONDS)
        if self._thread.is_alive():
            # A descendant inherited stderr, so end of file never comes. The
            # drain checks the flag every 100ms, so this returns promptly.
            self._stop.set()
            self._thread.join(timeout=_STDIO_DRAIN_GRACE_SECONDS)


@asynccontextmanager
async def _open_stdio_client(stdio_target: StdioTarget):
    with tempfile.TemporaryDirectory(prefix="airlock-stdio-") as workdir:
        parameters = StdioServerParameters(
            command=stdio_target.command,
            args=list(stdio_target.args),
            env=_stdio_child_environment(workdir),
            cwd=workdir,
        )
        # A server that fails to start says why on stderr. Discarding it left
        # an operator with a bare transport failure and nothing to act on.
        errlog = _BoundedStderr()
        try:
            async with Client(
                stdio_client(parameters, errlog=errlog.stream),
                mode="auto",
            ) as client:
                yield client
        except Exception as exc:
            raise StdioLaunchError(stdio_target, errlog.tail()) from exc
        finally:
            errlog.close()


@asynccontextmanager
async def _open_client(
    target: Any,
    *,
    binding: TargetBinding | None = None,
    stdio_target: StdioTarget | None = None,
    headers: Mapping[str, str] | None = None,
    max_response_bytes: int = 4 * 1024 * 1024,
):
    if stdio_target is not None:
        # Launching the audited server is the one place Airlock executes the
        # thing it distrusts. The command comes from deployment configuration,
        # the environment is not inherited, and the working directory is a
        # throwaway the caller owns.
        async with _open_stdio_client(stdio_target) as client:
            yield client
        return
    if isinstance(target, str):
        if binding is None:
            raise ValueError("URL targets require a validated target binding")
        timeout = httpx2.Timeout(30.0, read=300.0)
        async with httpx2.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=timeout,
            transport=BoundedAuditTransport(
                create_pinned_httpx2_transport(binding),
                max_response_bytes=max_response_bytes,
            ),
            headers=dict(headers or {}),
        ) as http_client:
            transport = streamable_http_client(
                target,
                http_client=http_client,
            )
            async with Client(transport, mode="auto") as client:
                yield client
        return
    async with Client(target, mode="auto") as client:
        yield client
