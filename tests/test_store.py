import json

import pytest

from airlock.models import (
    DeclaredScope,
    EvidenceEvent,
    EventKind,
    ObservationCapabilities,
    ProbeRecord,
)
from airlock.store import CaseIntegrityError, JsonCaseStore


def test_create_case_persists_a_reloadable_report(tmp_path):
    store = JsonCaseStore(tmp_path)

    created = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(
            egress_hosts=["fixture.test"],
            filesystem_roots=["/workspace/documents"],
        ),
        observation_capabilities=ObservationCapabilities(
            mcp_traffic=True,
            tool_results=True,
            server_egress=False,
            server_filesystem=False,
        ),
    )

    assert created.case_id.startswith("af_")
    assert created.disclaimer == (
        "Airlock reports what it observed. Absence of a finding is not proof of safety."
    )
    assert created.target_url == "http://fixture.test/mcp"

    reloaded = store.load_case(created.case_id)
    assert reloaded == created
    report_path = tmp_path / created.case_id / "airlock-report.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["airlock_version"] == "0.1.0"
    assert report["audited_at"] is None
    assert report["observations"] == []
    assert report["findings"] == []
    assert "events" not in report
    assert "checks" not in report


def test_integrity_key_detects_persisted_report_tampering(tmp_path):
    store = JsonCaseStore(tmp_path, integrity_key="s" * 32)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    report_path = tmp_path / case.case_id / "airlock-report.json"
    report_path.write_text(
        report_path.read_text(encoding="utf-8").replace(
            '"enforcement_active": false',
            '"enforcement_active": true',
        ),
        encoding="utf-8",
    )

    with pytest.raises(CaseIntegrityError, match="integrity verification failed"):
        store.load_case(case.case_id)


def test_integrity_key_signs_and_verifies_downloadable_artifacts(tmp_path):
    store = JsonCaseStore(tmp_path, integrity_key="s" * 32)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    store.write_json_artifact(
        case.case_id,
        "airlock-policy.json",
        {"mcp_servers": []},
    )

    assert b'"mcp_servers": []' in store.read_artifact(
        case.case_id,
        "airlock-policy.json",
    )

    policy_path = tmp_path / case.case_id / "airlock-policy.json"
    policy_path.write_text('{"mcp_servers": ["tampered"]}\n', encoding="utf-8")
    with pytest.raises(CaseIntegrityError, match="integrity verification failed"):
        store.read_artifact(case.case_id, "airlock-policy.json")


def test_store_enforces_private_directory_and_file_modes(tmp_path):
    root = tmp_path / "cases"
    root.mkdir(mode=0o755)
    store = JsonCaseStore(root, integrity_key="s" * 32)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    case_directory = root / case.case_id

    assert root.stat().st_mode & 0o777 == 0o700
    assert case_directory.stat().st_mode & 0o777 == 0o700
    assert (case_directory / "airlock-report.json").stat().st_mode & 0o777 == 0o600
    assert (case_directory / ".airlock-report.json.sig").stat().st_mode & 0o777 == 0o600


def test_integrity_key_must_have_at_least_32_bytes(tmp_path):
    with pytest.raises(ValueError, match="at least 32 bytes"):
        JsonCaseStore(tmp_path, integrity_key="short")


def test_append_event_is_durable(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    event = EvidenceEvent(
        event_id="ev_1",
        probe_id="probe_1",
        tool="search_docs",
        kind=EventKind.TOOL_CALL,
        sensor="mcp_transcript",
        details={"arguments_digest": "sha256:abc"},
    )

    store.append_event(case.case_id, event)

    assert store.load_case(case.case_id).events == [event]


def test_append_event_is_idempotent_by_event_id(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    event = EvidenceEvent(
        event_id="ev_retry_1",
        probe_id="probe_retry_1",
        tool="search_docs",
        kind=EventKind.TOOL_RESULT,
        sensor="mcp_transcript",
    )

    store.append_event(case.case_id, event)
    store.append_event(case.case_id, event)

    assert store.load_case(case.case_id).events == [event]


def test_runtime_event_retention_is_bounded_and_counted(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    for index in range(4):
        store.append_runtime_event(
            case.case_id,
            EvidenceEvent(
                event_id=f"runtime_event_{index}",
                probe_id=f"runtime_probe_{index}",
                tool="search_docs",
                kind=EventKind.TOOL_CALL,
                sensor="mcp_transcript",
            ),
            max_runtime_events=2,
        )

    persisted = store.load_case(case.case_id)
    assert [event.event_id for event in persisted.events] == [
        "runtime_event_2",
        "runtime_event_3",
    ]
    assert persisted.runtime_events_dropped == 2


def test_append_probe_is_durable_and_idempotent(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    probe = ProbeRecord(
        probe_id="probe_1",
        tool="search_docs",
        kind="baseline",
        request={"query": "airlock"},
        accepted=True,
        response_digest="sha256:result",
    )

    store.append_probe(case.case_id, probe)
    store.append_probe(case.case_id, probe)

    assert store.load_case(case.case_id).probes == [probe]


def test_append_probe_enforces_persisted_case_budget(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    store.save_case(case.model_copy(update={"probe_budget": 1}))
    first = ProbeRecord(
        probe_id="probe_first",
        tool="search_docs",
        kind="baseline",
        accepted=True,
    )
    second = ProbeRecord(
        probe_id="probe_second",
        tool="get_document",
        kind="baseline",
        accepted=True,
    )

    store.append_probe(case.case_id, first)

    try:
        store.append_probe(case.case_id, second)
    except ValueError as exc:
        assert "probe budget" in str(exc)
    else:
        raise AssertionError("probe budget was not enforced")

    assert store.load_case(case.case_id).probes_run == 1


def test_probe_budget_is_reserved_before_execution_and_completion_is_atomic(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    store.save_case(case.model_copy(update={"probe_budget": 1}))
    reservation = ProbeRecord(
        probe_id="probe_reserved",
        tool="search_docs",
        kind="baseline",
        accepted=False,
        completed=False,
    )

    assert store.reserve_probe(case.case_id, reservation) is True
    assert store.reserve_probe(case.case_id, reservation) is False
    with pytest.raises(ValueError, match="probe budget"):
        store.reserve_probe(
            case.case_id,
            ProbeRecord(
                probe_id="probe_over_budget",
                tool="get_document",
                kind="baseline",
                accepted=False,
                completed=False,
            ),
        )

    completed = reservation.model_copy(
        update={
            "accepted": True,
            "completed": True,
            "response_digest": "sha256:done",
        }
    )
    store.complete_probe(case.case_id, completed)

    persisted = store.load_case(case.case_id)
    assert persisted.probes == [completed]
    assert persisted.probes_run == 1
