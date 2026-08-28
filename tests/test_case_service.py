import pytest

from airlock.case_service import CaseService
from airlock.detectors import detect_findings
from airlock.models import (
    CaseStatus,
    CheckName,
    DecisionChoice,
    DeclaredScope,
    EvidenceStrength,
    EvidenceMode,
    Finding,
    FindingStatus,
    ObservationCapabilities,
    ProbeRecord,
    ToolDeclaration,
    Verdict,
)
from airlock.store import JsonCaseStore
from airlock.target_policy import TargetValidationError


def _complete_checks(case, *, overrides=None):
    checks = detect_findings(
        declarations=case.declared_tools,
        events=case.events,
        probes=case.probes,
        canaries={},
        scope=case.declared_scope,
        capabilities=case.observation_capabilities,
        evidence_mode=case.evidence_mode,
    )
    by_key = {(finding.tool, finding.check): finding for finding in checks}
    for finding in overrides or []:
        by_key[(finding.tool, finding.check)] = finding
    return list(by_key.values())


def test_record_inventory_binds_case_to_canonical_tool_catalog(tmp_path):
    service = CaseService(
        JsonCaseStore(tmp_path),
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["93.184.216.34"],
    )
    case = service.open_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(egress_hosts=["fixture.example"]),
        evidence_mode=EvidenceMode.TRANSCRIPT_ONLY,
        capabilities=ObservationCapabilities(
            mcp_traffic=True,
            tool_results=True,
            server_egress=False,
            server_filesystem=False,
        ),
    )
    declarations = [
        ToolDeclaration(
            name="search_docs",
            description="Search documentation",
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            annotations={"readOnlyHint": True},
        )
    ]

    inventoried = service.record_inventory(
        case.case_id,
        declarations=declarations,
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )

    assert inventoried.status == CaseStatus.INVENTORIED
    assert inventoried.declared_tools == declarations
    assert inventoried.catalog_digest.startswith("sha256:")
    assert inventoried.proxy_url == (
        f"https://airlock.example/cases/{case.case_id}/mcp"
    )
    assert inventoried.target_binding is not None
    assert inventoried.target_binding.hostname == "fixture.example"
    assert inventoried.target_binding.resolved_ips == ["93.184.216.34"]


def test_open_case_rejects_target_that_resolves_to_private_address(tmp_path):
    service = CaseService(
        JsonCaseStore(tmp_path),
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["169.254.169.254"],
    )

    with pytest.raises(TargetValidationError):
        service.open_case(
            target_url="https://metadata.example/mcp",
            declared_scope=DeclaredScope(),
            evidence_mode=EvidenceMode.TRANSCRIPT_ONLY,
            capabilities=ObservationCapabilities(
                mcp_traffic=True,
                tool_results=True,
                server_egress=False,
                server_filesystem=False,
            ),
        )


def test_revalidate_target_fails_when_dns_binding_changes(tmp_path):
    answers = [["93.184.216.34"], ["93.184.216.35"]]
    service = CaseService(
        JsonCaseStore(tmp_path),
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: answers.pop(0),
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

    with pytest.raises(TargetValidationError, match="DNS binding changed"):
        service.revalidate_target(case.case_id)


def test_inventory_only_case_cannot_advance_to_human_decision(tmp_path):
    service = CaseService(
        JsonCaseStore(tmp_path),
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
    service.record_inventory(
        case.case_id,
        declarations=[ToolDeclaration(name="search_docs")],
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )

    with pytest.raises(ValueError, match="completed audit"):
        service.mark_awaiting_decision(case.case_id)


def test_record_checks_rejects_an_incomplete_detector_matrix(tmp_path):
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
    service.record_inventory(
        case.case_id,
        declarations=[ToolDeclaration(name="search_docs")],
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    service.start_probing(case.case_id)
    store.append_probe(
        case.case_id,
        ProbeRecord(
            probe_id="probe_search",
            tool="search_docs",
            kind="baseline",
            accepted=True,
        ),
    )

    with pytest.raises(ValueError, match="exactly one result"):
        service.record_checks(case.case_id, checks=[])


def test_annotation_divergence_forces_literal_approval_gate(tmp_path):
    store = JsonCaseStore(tmp_path)
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["93.184.216.34"],
    )
    case = service.open_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        evidence_mode=EvidenceMode.CONTROLLED_FIXTURE,
        capabilities=ObservationCapabilities.controlled_fixture(),
    )
    service.record_inventory(
        case.case_id,
        declarations=[
            ToolDeclaration(
                name="export_report",
                annotations={"readOnlyHint": True},
            )
        ],
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    service.start_probing(case.case_id)
    store.append_probe(
        case.case_id,
        ProbeRecord(
            probe_id="probe_export",
            tool="export_report",
            kind="baseline",
            accepted=True,
        ),
    )
    service.record_checks(
        case.case_id,
        checks=_complete_checks(
            store.load_case(case.case_id),
            overrides=[
            Finding(
                tool="export_report",
                check=CheckName.ANNOTATION_DIVERGENCE,
                status=FindingStatus.FINDING,
                verdict=Verdict.BLOCK,
                evidence_strength=EvidenceStrength.DIRECT,
                sensor="fixture_filesystem",
                explanation="export_report wrote after claiming read-only behavior",
            )
            ],
        ),
    )

    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["export_report"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    assert sealed.decision is not None
    assert sealed.decision.approval_required_tools == ["export_report"]


def test_any_observed_finding_forces_literal_approval_gate(tmp_path):
    store = JsonCaseStore(tmp_path)
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["93.184.216.34"],
    )
    case = service.open_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        evidence_mode=EvidenceMode.CONTROLLED_FIXTURE,
        capabilities=ObservationCapabilities.controlled_fixture(),
    )
    service.record_inventory(
        case.case_id,
        declarations=[
            ToolDeclaration(
                name="search_docs",
                annotations={"readOnlyHint": True},
            )
        ],
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    service.start_probing(case.case_id)
    store.append_probe(
        case.case_id,
        ProbeRecord(
            probe_id="probe_search",
            tool="search_docs",
            kind="baseline",
            accepted=True,
        ),
    )
    service.record_checks(
        case.case_id,
        checks=_complete_checks(
            store.load_case(case.case_id),
            overrides=[
            Finding(
                tool="search_docs",
                check=CheckName.CANARY_EXFILTRATION,
                status=FindingStatus.FINDING,
                verdict=Verdict.CRITICAL,
                evidence_strength=EvidenceStrength.EXTERNAL_ORACLE,
                sensor="fixture_canary_sink",
                explanation="A planted value reached the owned sink.",
            )
            ],
        ),
    )

    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    assert sealed.decision is not None
    assert sealed.decision.approval_required_tools == ["search_docs"]


def test_declared_write_or_destructive_tool_forces_literal_approval_gate(tmp_path):
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
    service.record_inventory(
        case.case_id,
        declarations=[
            ToolDeclaration(
                name="create_ticket",
                annotations={
                    "readOnlyHint": False,
                    "destructiveHint": True,
                },
            )
        ],
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    service.start_probing(case.case_id)
    store.append_probe(
        case.case_id,
        ProbeRecord(
            probe_id="probe_create_ticket",
            tool="create_ticket",
            kind="baseline",
            accepted=True,
        ),
    )
    service.record_checks(
        case.case_id,
        checks=_complete_checks(store.load_case(case.case_id)),
    )

    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_ALL,
        approved_tools=[],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    assert sealed.decision is not None
    assert sealed.decision.approval_required_tools == ["create_ticket"]
