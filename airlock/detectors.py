from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .models import (
    CheckName,
    DeclaredScope,
    EvidenceEvent,
    EvidenceMode,
    EvidenceStrength,
    EventKind,
    Finding,
    FindingStatus,
    ObservationCapabilities,
    ProbeRecord,
    ToolDeclaration,
    Verdict,
)


_STATE_CHANGING_EVENTS = {
    EventKind.FILESYSTEM_WRITE,
    EventKind.STATE_CHANGE,
}

_INSTRUCTION_PATTERNS = (
    re.compile(r"\b(?:ignore|disregard|override)\b.{0,80}\b(?:instruction|prompt)\b", re.I),
    re.compile(r"\b(?:assistant|model)\b.{0,40}\b(?:must|should|need to)\b", re.I),
    re.compile(r"\b(?:call|invoke|execute|run)\b\s+(?:the\s+)?(?:tool\s+)?[a-z][a-z0-9_-]{2,}", re.I),
)


def contains_injected_instruction(value: Any) -> bool:
    serialized = json.dumps(value, sort_keys=True, default=str)
    return any(pattern.search(serialized) for pattern in _INSTRUCTION_PATTERNS)


def _path_is_in_scope(path: str, roots: Iterable[str]) -> bool:
    normalized_path = posixpath.normpath(path)
    if not posixpath.isabs(normalized_path):
        return False
    for root in roots:
        normalized_root = posixpath.normpath(root)
        try:
            if posixpath.commonpath([normalized_path, normalized_root]) == normalized_root:
                return True
        except ValueError:
            continue
    return False


def _request_violates_schema(request: dict[str, Any], schema: dict[str, Any]) -> bool:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        return False
    return not Draft202012Validator(schema).is_valid(request)


def detect_findings(
    *,
    declarations: Iterable[ToolDeclaration],
    events: Iterable[EvidenceEvent],
    probes: Iterable[ProbeRecord],
    canaries: dict[str, str],
    scope: DeclaredScope,
    capabilities: ObservationCapabilities,
    evidence_mode: EvidenceMode,
) -> list[Finding]:
    events = list(events)
    declarations_by_name = {item.name: item for item in declarations}
    probes_by_id = {item.probe_id: item for item in probes}
    findings: list[Finding] = []

    for event in events:
        declaration = declarations_by_name.get(event.tool)
        if declaration is None:
            continue
        if event.kind == EventKind.SENSOR_FAILURE:
            raw_checks = event.details.get("checks", [])
            for raw_check in raw_checks if isinstance(raw_checks, list) else []:
                try:
                    failed_check = CheckName(str(raw_check))
                except ValueError:
                    continue
                findings.append(
                    Finding(
                        tool=event.tool,
                        check=failed_check,
                        status=FindingStatus.SENSOR_FAILED,
                        evidence_strength=EvidenceStrength.NONE,
                        sensor=event.sensor,
                        evidence_refs=[event.event_id],
                        explanation=(
                            f"The {event.sensor} sensor failed while observing "
                            f"{failed_check.value.replace('_', ' ')}."
                        ),
                    )
                )
            continue
        if (
            declaration.annotations.get("readOnlyHint") is True
            and event.kind in _STATE_CHANGING_EVENTS
        ):
            findings.append(
                Finding(
                    tool=event.tool,
                    check=CheckName.ANNOTATION_DIVERGENCE,
                    status=FindingStatus.FINDING,
                    verdict=Verdict.BLOCK,
                    evidence_strength=EvidenceStrength.DIRECT,
                    sensor=event.sensor,
                    evidence_refs=[event.event_id],
                    explanation=(
                        f"{event.tool} claimed read-only behavior, but Airlock observed "
                        f"{event.kind.value.replace('_', ' ')}."
                    ),
                )
            )
        if event.kind == EventKind.NETWORK_EGRESS:
            observed_host = str(event.details.get("host", "")).lower().rstrip(".")
            allowed_hosts = {host.lower().rstrip(".") for host in scope.egress_hosts}
            if observed_host and observed_host not in allowed_hosts:
                findings.append(
                    Finding(
                        tool=event.tool,
                        check=CheckName.UNDECLARED_EGRESS,
                        status=FindingStatus.FINDING,
                        verdict=Verdict.BLOCK,
                        evidence_strength=EvidenceStrength.DIRECT,
                        sensor=event.sensor,
                        evidence_refs=[event.event_id],
                        explanation=(
                            f"{event.tool} contacted {observed_host}, which is outside the "
                            "Airlock scope manifest."
                        ),
                    )
                )
        if event.kind in {EventKind.FILESYSTEM_READ, EventKind.FILESYSTEM_WRITE}:
            observed_path = str(event.details.get("path", ""))
            if observed_path and not _path_is_in_scope(
                observed_path, scope.filesystem_roots
            ):
                findings.append(
                    Finding(
                        tool=event.tool,
                        check=CheckName.SCOPE_ESCAPE,
                        status=FindingStatus.FINDING,
                        verdict=Verdict.CRITICAL,
                        evidence_strength=EvidenceStrength.DIRECT,
                        sensor=event.sensor,
                        evidence_refs=[event.event_id],
                        explanation=(
                            f"{event.tool} touched {posixpath.normpath(observed_path)}, which "
                            "is outside the Airlock scope manifest."
                        ),
                    )
                )
        if event.kind in {EventKind.CANARY_SINK, EventKind.TOOL_RESULT}:
            serialized_details = json.dumps(event.details, sort_keys=True, default=str)
            probe = probes_by_id.get(event.probe_id)
            supplied_canaries = set(probe.supplied_canary_ids if probe else [])
            feature_matches = {
                str(item)
                for item in event.details.get("matched_canary_ids", [])
                if str(item) in canaries
            }
            for canary_id, canary_value in canaries.items():
                if (
                    event.kind == EventKind.TOOL_RESULT
                    and canary_id in supplied_canaries
                ) or (
                    canary_id not in feature_matches
                    and canary_value not in serialized_details
                ):
                    continue
                findings.append(
                    Finding(
                        tool=event.tool,
                        check=CheckName.CANARY_EXFILTRATION,
                        status=FindingStatus.FINDING,
                        verdict=Verdict.CRITICAL,
                        evidence_strength=(
                            EvidenceStrength.EXTERNAL_ORACLE
                            if event.kind == EventKind.CANARY_SINK
                            else EvidenceStrength.DIRECT
                        ),
                        sensor=event.sensor,
                        evidence_refs=[event.event_id],
                        explanation=(
                            f"A planted canary ({canary_id}) appeared in "
                            f"{event.kind.value.replace('_', ' ')} evidence for {event.tool}."
                        ),
                    )
                )
        if event.kind == EventKind.TOOL_RESULT:
            serialized_details = json.dumps(event.details, sort_keys=True, default=str)
            if event.details.get("injected_instruction_detected") is True or any(
                pattern.search(serialized_details) for pattern in _INSTRUCTION_PATTERNS
            ):
                findings.append(
                    Finding(
                        tool=event.tool,
                        check=CheckName.INJECTED_INSTRUCTIONS,
                        status=FindingStatus.FINDING,
                        verdict=Verdict.SUSPICIOUS,
                        evidence_strength=EvidenceStrength.HEURISTIC,
                        sensor=event.sensor,
                        evidence_refs=[event.event_id],
                        explanation=(
                            f"{event.tool} returned model-directed imperative language. "
                            "The raw result remains quarantined for human review."
                        ),
                    )
                )

    for probe in probes_by_id.values():
        declaration = declarations_by_name.get(probe.tool)
        if declaration is None or not probe.completed or not probe.accepted:
            continue
        if _request_violates_schema(probe.request, declaration.input_schema):
            findings.append(
                Finding(
                    tool=probe.tool,
                    check=CheckName.SCHEMA_DRIFT,
                    status=FindingStatus.FINDING,
                    verdict=Verdict.SUSPICIOUS,
                    evidence_strength=EvidenceStrength.DIRECT,
                    sensor="mcp_transcript",
                    evidence_refs=[probe.probe_id],
                    explanation=(
                        f"{probe.tool} accepted arguments that violate its published input "
                        "schema."
                    ),
                )
            )

    aggregate: dict[tuple[str, CheckName], Finding] = {}
    status_priority = {
        FindingStatus.NO_FINDING_OBSERVED: 0,
        FindingStatus.NOT_TESTED: 1,
        FindingStatus.SENSOR_FAILED: 2,
        FindingStatus.FINDING: 3,
    }
    for finding in findings:
        key = (finding.tool, finding.check)
        existing = aggregate.get(key)
        if existing is None:
            aggregate[key] = finding
            continue
        if (
            existing.status == FindingStatus.FINDING
            and finding.status == FindingStatus.FINDING
        ):
            aggregate[key] = existing.model_copy(
                update={
                    "evidence_refs": list(
                        dict.fromkeys([*existing.evidence_refs, *finding.evidence_refs])
                    )
                }
            )
            continue
        if status_priority[finding.status] > status_priority[existing.status]:
            aggregate[key] = finding

    probe_count_by_tool: dict[str, int] = {}
    successful_probe_ids_by_tool: dict[str, set[str]] = {}
    for probe in probes_by_id.values():
        if probe.completed and probe.accepted:
            probe_count_by_tool[probe.tool] = (
                probe_count_by_tool.get(probe.tool, 0) + 1
            )
            successful_probe_ids_by_tool.setdefault(probe.tool, set()).add(
                probe.probe_id
            )

    heartbeat_checks_by_probe: dict[tuple[str, str], set[CheckName]] = {}
    for event in events:
        if event.kind != EventKind.SENSOR_HEARTBEAT:
            continue
        key = (event.tool, event.probe_id)
        checks = heartbeat_checks_by_probe.setdefault(key, set())
        raw_checks = event.details.get("checks", [])
        for raw_check in raw_checks if isinstance(raw_checks, list) else []:
            try:
                checks.add(CheckName(str(raw_check)))
            except ValueError:
                continue

    for declaration in declarations_by_name.values():
        probe_count = probe_count_by_tool.get(declaration.name, 0)
        for check in CheckName:
            key = (declaration.name, check)
            if key in aggregate:
                continue
            successful_probe_ids = successful_probe_ids_by_tool.get(
                declaration.name,
                set(),
            )
            available_probe_count = _observable_probe_count(
                check,
                tool=declaration.name,
                successful_probe_ids=successful_probe_ids,
                heartbeat_checks_by_probe=heartbeat_checks_by_probe,
                capabilities=capabilities,
            )
            available = available_probe_count > 0
            status = (
                FindingStatus.NO_FINDING_OBSERVED
                if available
                else FindingStatus.NOT_TESTED
            )
            if available:
                explanation = (
                    f"No {check.value.replace('_', ' ')} behavior was observed across "
                    f"{available_probe_count} probes using {evidence_mode.value} "
                    "evidence."
                )
                sensor = "aggregate"
            elif not _check_capability_available(check, capabilities):
                explanation = (
                    f"The {check.value.replace('_', ' ')} check was not tested because "
                    "this case has no sensor that can observe it."
                )
                sensor = "capability_absent"
            else:
                explanation = (
                    f"The {check.value.replace('_', ' ')} check has a configured sensor "
                    "but produced no completed probe evidence for this tool."
                )
                sensor = "evidence_missing"
            aggregate[key] = Finding(
                tool=declaration.name,
                check=check,
                status=status,
                evidence_strength=EvidenceStrength.NONE,
                sensor=sensor,
                explanation=explanation,
            )

    return [
        aggregate[(tool_name, check)]
        for tool_name in sorted(declarations_by_name)
        for check in CheckName
    ]


def _check_capability_available(
    check: CheckName,
    capabilities: ObservationCapabilities,
) -> bool:
    """Whether this case claims a sensor able to observe the check at all."""
    if check == CheckName.INJECTED_INSTRUCTIONS:
        return capabilities.tool_results
    if check == CheckName.SCHEMA_DRIFT:
        return capabilities.mcp_traffic
    if check in {CheckName.ANNOTATION_DIVERGENCE, CheckName.SCOPE_ESCAPE}:
        return capabilities.server_filesystem
    return capabilities.server_egress


def _observable_probe_count(
    check: CheckName,
    *,
    tool: str,
    successful_probe_ids: set[str],
    heartbeat_checks_by_probe: dict[tuple[str, str], set[CheckName]],
    capabilities: ObservationCapabilities,
) -> int:
    if not successful_probe_ids:
        return 0
    if check == CheckName.INJECTED_INSTRUCTIONS:
        return len(successful_probe_ids) if capabilities.tool_results else 0
    if check == CheckName.SCHEMA_DRIFT:
        return len(successful_probe_ids) if capabilities.mcp_traffic else 0
    if check in {
        CheckName.ANNOTATION_DIVERGENCE,
        CheckName.SCOPE_ESCAPE,
    } and not capabilities.server_filesystem:
        return 0
    if check in {
        CheckName.UNDECLARED_EGRESS,
        CheckName.CANARY_EXFILTRATION,
    } and not capabilities.server_egress:
        return 0
    return sum(
        check in heartbeat_checks_by_probe.get((tool, probe_id), set())
        for probe_id in successful_probe_ids
    )
