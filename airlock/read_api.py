"""Read-only HTTP views of case state for the Airlock operator interface.

The control MCP server deliberately reduces tool names, descriptions and
detector explanations to digests, because those values re-enter the model.
This router serves the same cases to a human instead, so it returns the
declared text verbatim. Every consumer must render it as inert text: the
declaration column quotes an untrusted server in that server's own words.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .models import CaseRecord, FindingStatus
from .store import CaseIntegrityError, JsonCaseStore

_NO_CACHE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


def _summary(case: CaseRecord) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "target_url": case.target_url,
        "status": case.status.value,
        "created_at": case.created_at.isoformat(),
        "audited_at": (
            case.audit_completed_at.isoformat()
            if case.audit_completed_at is not None
            else None
        ),
        "evidence_mode": case.evidence_mode.value,
        "tool_count": len(case.declared_tools),
        "finding_count": sum(
            check.status == FindingStatus.FINDING for check in case.checks
        ),
        "probe_budget": case.probe_budget,
        "probes_run": case.probes_run,
        "enforcement_active": case.enforcement_active,
        "disclaimer": case.disclaimer,
    }


def _detail(case: CaseRecord) -> dict[str, Any]:
    accepted_probes: dict[str, int] = {}
    for probe in case.probes:
        if probe.completed:
            accepted_probes[probe.tool] = accepted_probes.get(probe.tool, 0) + 1
    return {
        **_summary(case),
        "airlock_version": case.airlock_version,
        "protocol_version": case.protocol_version,
        "catalog_digest": case.catalog_digest,
        "proxy_url": case.proxy_url,
        "observation_capabilities": case.observation_capabilities.model_dump(
            mode="json"
        ),
        "declared_scope": case.declared_scope.model_dump(mode="json"),
        "runtime_events_dropped": case.runtime_events_dropped,
        "declared_tools": [
            {
                "name": declaration.name,
                "description": declaration.description,
                "annotations": declaration.annotations,
                "input_schema": declaration.input_schema,
                "probes_run": accepted_probes.get(declaration.name, 0),
            }
            for declaration in case.declared_tools
        ],
        "checks": [
            {
                "tool": check.tool,
                "check": check.check.value,
                "status": check.status.value,
                "verdict": (
                    check.verdict.value if check.verdict is not None else None
                ),
                "evidence_strength": check.evidence_strength.value,
                "sensor": check.sensor,
                "evidence_refs": list(check.evidence_refs),
                "explanation": check.explanation,
            }
            for check in case.checks
        ],
        "observations": [
            {
                "event_id": event.event_id,
                "probe_id": event.probe_id,
                "tool": event.tool,
                "kind": event.kind.value,
                "sensor": event.sensor,
                "observed_at": event.observed_at.isoformat(),
            }
            for event in case.events
        ],
        "decision": (
            case.decision.model_dump(mode="json")
            if case.decision is not None
            else None
        ),
    }


def create_read_router(store: JsonCaseStore) -> APIRouter:
    router = APIRouter()

    @router.get("/api/cases")
    async def list_cases() -> JSONResponse:
        cases = []
        for case_id in store.list_case_ids():
            try:
                cases.append(_summary(store.load_case(case_id)))
            except (CaseIntegrityError, FileNotFoundError, ValueError):
                cases.append(
                    {
                        "case_id": case_id,
                        "status": "unreadable",
                        "target_url": None,
                        "unreadable": True,
                    }
                )
        cases.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return JSONResponse({"cases": cases}, headers=_NO_CACHE)

    @router.get("/api/cases/{case_id}")
    async def read_case(case_id: str) -> JSONResponse:
        try:
            case = store.load_case(case_id)
        except CaseIntegrityError:
            return JSONResponse(
                {"detail": "Case state failed integrity verification"},
                status_code=409,
                headers=_NO_CACHE,
            )
        except (FileNotFoundError, ValueError):
            return JSONResponse(
                {"detail": "Case not found"},
                status_code=404,
                headers=_NO_CACHE,
            )
        return JSONResponse(_detail(case), headers=_NO_CACHE)

    return router


__all__ = ["create_read_router"]
