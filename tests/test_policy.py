import json
import pytest

from airlock.case_service import CaseService
from airlock.detectors import detect_findings
from airlock.models import (
    DecisionChoice,
    DeclaredScope,
    EvidenceMode,
    ObservationCapabilities,
    ProbeRecord,
    ToolDeclaration,
)
from airlock.policy import (
    DecisionRequiredError,
    PolicyInvariantError,
    compile_connector_manifest,
    compile_policy,
)
from airlock.store import JsonCaseStore


def _inventoried_case(tmp_path):
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
    declarations = [
        ToolDeclaration(name="search_docs", annotations={"readOnlyHint": True}),
        ToolDeclaration(name="create_ticket", annotations={"readOnlyHint": False}),
        ToolDeclaration(name="export_report", annotations={"readOnlyHint": True}),
    ]
    inventoried = service.record_inventory(
        case.case_id,
        declarations=declarations,
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    service.start_probing(case.case_id)
    for tool in declarations:
        service.store.append_probe(
            case.case_id,
            ProbeRecord(
                probe_id=f"probe_{tool.name}",
                tool=tool.name,
                kind="baseline",
                accepted=True,
            ),
        )
    inventoried = service.store.load_case(case.case_id)
    checks = detect_findings(
        declarations=inventoried.declared_tools,
        events=inventoried.events,
        probes=inventoried.probes,
        canaries={},
        scope=inventoried.declared_scope,
        capabilities=inventoried.observation_capabilities,
        evidence_mode=inventoried.evidence_mode,
    )
    return service, service.record_checks(case.case_id, checks=checks)


def test_policy_cannot_be_emitted_before_recorded_human_decision(tmp_path):
    _, case = _inventoried_case(tmp_path)

    with pytest.raises(DecisionRequiredError):
        compile_policy(case, connector_name="fixture-via-airlock")


def test_selected_policy_enables_approval_gated_tools_and_disables_the_rest(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs", "create_ticket"],
        approval_required_tools=["create_ticket"],
        decision_source="trueforge_approval",
    )

    policy = compile_policy(sealed, connector_name="fixture-via-airlock")

    assert policy == {
        "mcp_servers": [
            {
                "name": "fixture-via-airlock",
                "enable_tools": ["create_ticket", "search_docs"],
                "disable_tools": ["export_report"],
                "require_approval_for_tools": ["create_ticket"],
                "preload": False,
            }
        ]
    }
    assert compile_connector_manifest(
        sealed,
        connector_name="fixture-via-airlock",
    ) == {
        "manifest": {
            "type": "remote",
            "name": "fixture-via-airlock",
            "url": sealed.proxy_url,
            "description": f"Airlock-enforced connector for {sealed.case_id}",
        }
    }


def test_policy_fails_closed_if_persisted_audit_completion_is_missing(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    inconsistent = sealed.model_copy(update={"audit_completed_at": None})

    with pytest.raises(PolicyInvariantError, match="completed audit"):
        compile_policy(inconsistent, connector_name="fixture-via-airlock")


def test_policy_fails_closed_if_detector_matrix_is_missing(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    inconsistent = sealed.model_copy(update={"checks": []})

    with pytest.raises(PolicyInvariantError, match="detector matrix"):
        compile_policy(inconsistent, connector_name="fixture-via-airlock")


def test_policy_fails_closed_if_a_declared_tool_has_no_persisted_probe(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    incomplete = sealed.model_copy(
        update={
            "probes": [
                probe for probe in sealed.probes if probe.tool != "export_report"
            ]
        }
    )

    with pytest.raises(PolicyInvariantError, match="every declared tool"):
        compile_connector_manifest(
            incomplete,
            connector_name="fixture-via-airlock",
        )


def test_policy_fails_closed_if_decision_names_an_unknown_tool(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    assert sealed.decision is not None
    inconsistent = sealed.model_copy(
        update={
            "decision": sealed.decision.model_copy(
                update={"approved_tools": ["unknown_tool"]}
            )
        }
    )

    with pytest.raises(PolicyInvariantError, match="inventoried catalog"):
        compile_policy(inconsistent, connector_name="fixture-via-airlock")


def test_policy_recomputes_catalog_digest_and_minimum_approval_gate(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["create_ticket"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    assert sealed.decision is not None
    without_required_gate = sealed.model_copy(
        update={
            "decision": sealed.decision.model_copy(
                update={"approval_required_tools": []}
            )
        }
    )
    wrong_catalog_digest = sealed.model_copy(
        update={"catalog_digest": "sha256:tampered"}
    )

    with pytest.raises(PolicyInvariantError, match="minimum approval"):
        compile_policy(without_required_gate, connector_name="fixture-via-airlock")
    with pytest.raises(PolicyInvariantError, match="catalog digest"):
        compile_policy(wrong_catalog_digest, connector_name="fixture-via-airlock")


def test_connector_manifest_rejects_tampered_proxy_url(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_SELECTED,
        approved_tools=["search_docs"],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )
    tampered = sealed.model_copy(
        update={"proxy_url": "https://fixture.example/mcp"}
    )

    with pytest.raises(PolicyInvariantError, match="proxy URL"):
        compile_connector_manifest(
            tampered,
            connector_name="fixture-via-airlock",
            expected_proxy_url=(
                f"https://airlock.example/cases/{sealed.case_id}/mcp"
            ),
        )


def test_connector_manifest_carries_the_proxy_credential_when_one_is_set(tmp_path):
    # Without it the artifact does not paste into a harness unedited: the
    # proxy answers 401 and the connector never connects.
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_ALL,
        approved_tools=[],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    manifest = compile_connector_manifest(
        sealed,
        connector_name="fixture-via-airlock",
        proxy_authorization="Bearer runtime-token",
    )["manifest"]

    assert manifest["auth"] == {
        "type": "header",
        "headers": {"Authorization": "Bearer runtime-token"},
    }


def test_connector_manifest_omits_auth_when_the_proxy_has_no_token(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_ALL,
        approved_tools=[],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    manifest = compile_connector_manifest(
        sealed, connector_name="fixture-via-airlock"
    )["manifest"]

    assert "auth" not in manifest


def test_an_empty_proxy_credential_is_refused(tmp_path):
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_ALL,
        approved_tools=[],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    with pytest.raises(PolicyInvariantError, match="cannot be empty"):
        compile_connector_manifest(
            sealed,
            connector_name="fixture-via-airlock",
            proxy_authorization="   ",
        )


def test_the_report_and_policy_stay_free_of_the_proxy_credential(tmp_path):
    # Only the connector carries a secret. The evidence report and the policy
    # remain shareable.
    service, case = _inventoried_case(tmp_path)
    sealed = service.seal_case(
        case.case_id,
        choice=DecisionChoice.APPROVE_ALL,
        approved_tools=[],
        approval_required_tools=[],
        decision_source="trueforge_approval",
    )

    policy = compile_policy(sealed, connector_name="fixture-via-airlock")

    assert "runtime-token" not in json.dumps(policy)
    assert "Authorization" not in json.dumps(policy)
