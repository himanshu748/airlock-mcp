from fastapi import FastAPI
from fastapi.testclient import TestClient

from airlock.case_service import CaseService
from airlock.main import create_app_from_env
from airlock.models import (
    CheckName,
    DeclaredScope,
    EvidenceMode,
    EvidenceStrength,
    Finding,
    FindingStatus,
    ObservationCapabilities,
    ProbeRecord,
    ToolDeclaration,
    Verdict,
)
from airlock.read_api import create_read_router
from airlock.store import JsonCaseStore


def _client(tmp_path):
    store = JsonCaseStore(tmp_path)
    app = FastAPI()
    app.include_router(create_read_router(store))
    return store, TestClient(app)


def _audited_case(store):
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
    declarations = [
        ToolDeclaration(
            name="search_docs",
            description="Search the corpus. Read only, we promise.",
            annotations={"readOnlyHint": True},
        ),
    ]
    service.record_inventory(
        case.case_id,
        declarations=declarations,
        protocol_version="2026-07-28",
        auth_context_fingerprint="sha256:anonymous",
    )
    service.start_probing(case.case_id)
    store.append_probe(
        case.case_id,
        ProbeRecord(
            probe_id="probe_search_docs",
            tool="search_docs",
            kind="baseline",
            accepted=True,
            completed=True,
        ),
    )
    checks = [
        Finding(
            tool="search_docs",
            check=check,
            status=(
                FindingStatus.FINDING
                if check == CheckName.ANNOTATION_DIVERGENCE
                else FindingStatus.NO_FINDING_OBSERVED
            ),
            verdict=(
                Verdict.BLOCK
                if check == CheckName.ANNOTATION_DIVERGENCE
                else None
            ),
            evidence_strength=EvidenceStrength.NONE,
            sensor="aggregate",
            explanation="search_docs claimed read-only, but Airlock observed a write.",
        )
        for check in CheckName
    ]
    return service.record_checks(case.case_id, checks=checks)


def test_case_list_is_empty_before_any_case_is_opened(tmp_path):
    _, client = _client(tmp_path)

    assert client.get("/api/cases").json() == {"cases": []}


def test_case_list_summarises_open_cases(tmp_path):
    store, client = _client(tmp_path)
    case = _audited_case(store)

    body = client.get("/api/cases").json()

    assert len(body["cases"]) == 1
    summary = body["cases"][0]
    assert summary["case_id"] == case.case_id
    assert summary["target_url"] == "https://fixture.example/mcp"
    assert summary["tool_count"] == 1
    assert summary["finding_count"] == 1


def test_case_detail_returns_declared_text_verbatim_for_the_human_reader(tmp_path):
    store, client = _client(tmp_path)
    case = _audited_case(store)

    detail = client.get(f"/api/cases/{case.case_id}").json()

    tool = detail["declared_tools"][0]
    assert tool["name"] == "search_docs"
    assert tool["description"] == "Search the corpus. Read only, we promise."
    assert tool["annotations"] == {"readOnlyHint": True}
    assert tool["probes_run"] == 1
    divergence = next(
        check
        for check in detail["checks"]
        if check["check"] == "annotation_divergence"
    )
    assert divergence["status"] == "finding"
    assert divergence["verdict"] == "block"
    assert "observed a write" in divergence["explanation"]
    assert detail["disclaimer"]


def test_unknown_case_is_not_found(tmp_path):
    _, client = _client(tmp_path)

    assert client.get("/api/cases/af_" + "0" * 32).status_code == 404
    assert client.get("/api/cases/not-a-case-id").status_code == 404


def test_operator_ui_is_off_by_default_in_production(tmp_path):
    # It carries no authentication of its own, so production must opt in.
    disabled = create_app_from_env(
        {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "off"),
            "AIRLOCK_PUBLIC_BASE_URL": "https://airlock.example",
            "AIRLOCK_CONTROL_BEARER_TOKEN": "c" * 32,
            "AIRLOCK_CASE_PROXY_BEARER_TOKEN": "p" * 32,
            "AIRLOCK_STATE_INTEGRITY_KEY": "k" * 32,
        }
    )

    assert "/api/cases" not in {route.path for route in disabled.routes}


def test_operator_ui_can_be_switched_off_in_development(tmp_path):
    disabled = create_app_from_env(
        {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "devoff"),
            "AIRLOCK_INSECURE_DEVELOPMENT": "true",
            "AIRLOCK_ENABLE_OPERATOR_UI": "false",
        }
    )

    assert "/api/cases" not in {route.path for route in disabled.routes}


def test_operator_ui_is_on_by_default_in_development(tmp_path):
    # A silent 404 on /ui/ is the worst possible default for a reader.
    app = create_app_from_env(
        {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "devon"),
            "AIRLOCK_INSECURE_DEVELOPMENT": "true",
        }
    )

    assert "/api/cases" in {route.path for route in app.routes}


def test_operator_ui_serves_the_inspection_page_when_enabled(tmp_path):
    app = create_app_from_env(
        {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "on"),
            "AIRLOCK_ENABLE_OPERATOR_UI": "true",
            "AIRLOCK_INSECURE_DEVELOPMENT": "true",
        }
    )
    client = TestClient(app)

    assert "/api/cases" in {route.path for route in app.routes}
    assert client.get("/api/cases").json() == {"cases": []}
    landing = client.get("/ui/")
    assert landing.status_code == 200
    assert "The server says it" in landing.text
    assert landing.headers["content-security-policy"].startswith("default-src 'none'")
    assert landing.headers["x-content-type-options"] == "nosniff"
    assert landing.headers["x-frame-options"] == "DENY"
    # The record shell is served statically and fills itself in from /api.
    record = client.get("/ui/record/")
    assert record.status_code == 200
    assert "Airlock inspection record" in record.text
    assert record.headers["content-security-policy"].startswith("default-src 'none'")
