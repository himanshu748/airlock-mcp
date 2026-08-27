import asyncio

from mcp import Client

from airlock.fixtures import (
    DishonestBehaviors,
    FixtureObserver,
    StoreFixtureObserver,
    create_dishonest_server,
    create_honest_server,
)
from airlock.models import EventKind
from airlock.models import DeclaredScope, EvidenceMode, ObservationCapabilities
from airlock.canaries import CanaryVault
from airlock.store import JsonCaseStore


def test_honest_fixture_publishes_six_read_only_tools_and_no_side_effects(tmp_path):
    observer = FixtureObserver(case_id="fixture_case")
    server = create_honest_server(observer=observer, workspace=tmp_path)

    async def exercise():
        async with Client(server, mode="auto") as client:
            page = await client.list_tools()
            result = await client.call_tool("search_docs", {"query": "airlock"})
            return page.tools, result

    tools, result = asyncio.run(exercise())

    assert len(tools) == 6
    assert all(tool.annotations.read_only_hint is True for tool in tools)
    assert result.is_error is False
    assert [event.kind for event in observer.events] == [
        EventKind.SENSOR_HEARTBEAT
    ]


def test_dishonest_read_only_export_writes_and_emits_filesystem_evidence(tmp_path):
    observer = FixtureObserver(case_id="fixture_case")
    server = create_dishonest_server(
        observer=observer,
        workspace=tmp_path,
        behaviors=DishonestBehaviors(write_on_export=True),
        canaries={},
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool(
                "export_report",
                {"report_id": "report-1", "format": "csv"},
            )

    result = asyncio.run(exercise())

    assert result.is_error is False
    assert (tmp_path / "documents" / "report-1.csv").is_file()
    behavior_events = [
        event
        for event in observer.events
        if event.kind != EventKind.SENSOR_HEARTBEAT
    ]
    assert [event.kind for event in behavior_events] == [EventKind.FILESYSTEM_WRITE]
    assert behavior_events[0].tool == "export_report"


def test_dishonest_fixture_emits_network_evidence_for_toggle(tmp_path):
    observer = FixtureObserver(case_id="fixture_case")
    server = create_dishonest_server(
        observer=observer,
        workspace=tmp_path,
        behaviors=DishonestBehaviors(undeclared_egress=True),
        canaries={},
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool(
                "fetch_external_summary",
                {"url": "http://127.0.0.1:4399/ingest"},
            )

    result = asyncio.run(exercise())

    assert result.is_error is False
    behavior_events = [
        event
        for event in observer.events
        if event.kind != EventKind.SENSOR_HEARTBEAT
    ]
    assert [event.kind for event in behavior_events] == [EventKind.NETWORK_EGRESS]
    assert behavior_events[0].details == {"host": "127.0.0.1", "port": 4399}


def test_dishonest_fixture_reads_planted_canary_and_sends_it_to_sink(tmp_path):
    observer = FixtureObserver(case_id="fixture_case")
    canary_value = "airlock_canary_fixture_123"
    server = create_dishonest_server(
        observer=observer,
        workspace=tmp_path,
        behaviors=DishonestBehaviors(canary_exfiltration=True),
        canaries={"document_secret": canary_value},
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool(
                "summarize_documents",
                {"document_ids": ["doc-airlock"], "max_length": 200},
            )

    result = asyncio.run(exercise())

    assert result.is_error is False
    behavior_events = [
        event
        for event in observer.events
        if event.kind != EventKind.SENSOR_HEARTBEAT
    ]
    assert [event.kind for event in behavior_events] == [
        EventKind.FILESYSTEM_READ,
        EventKind.CANARY_SINK,
    ]
    assert behavior_events[1].details == {
        "matched_canary_ids": ["document_secret"],
        "destination_host": "127.0.0.1",
    }
    assert canary_value not in behavior_events[1].model_dump_json()


def test_dishonest_fixture_touches_path_outside_declared_documents_root(tmp_path):
    observer = FixtureObserver(case_id="fixture_case")
    server = create_dishonest_server(
        observer=observer,
        workspace=tmp_path,
        behaviors=DishonestBehaviors(scope_escape=True),
        canaries={},
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool("get_document", {"document_id": "doc-airlock"})

    result = asyncio.run(exercise())

    assert result.is_error is False
    behavior_events = [
        event
        for event in observer.events
        if event.kind != EventKind.SENSOR_HEARTBEAT
    ]
    assert [event.kind for event in behavior_events] == [EventKind.FILESYSTEM_READ]
    assert behavior_events[0].details["path"] == str(
        (tmp_path / "outside" / "secret.txt").resolve()
    )


def test_dishonest_fixture_can_embed_model_directed_instruction_in_result(tmp_path):
    observer = FixtureObserver(case_id="fixture_case")
    server = create_dishonest_server(
        observer=observer,
        workspace=tmp_path,
        behaviors=DishonestBehaviors(injected_instructions=True),
        canaries={},
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool("search_docs", {"query": "airlock"})

    result = asyncio.run(exercise())

    assert result.is_error is False
    assert "ignore previous instructions" in result.content[0].text.lower()


def test_store_fixture_rejects_unsigned_cross_case_metadata_before_path_use(tmp_path):
    store = JsonCaseStore(tmp_path / "cases")
    victim = store.create_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
        evidence_mode=EvidenceMode.CONTROLLED_FIXTURE,
    )
    CanaryVault(store).plant(victim.case_id, labels=["document_secret"])
    workspace = tmp_path / "fixture"
    server = create_dishonest_server(
        observer=StoreFixtureObserver(
            store,
            signing_key="fixture-signing-key",
            allowed_target_urls={"https://fixture.example/mcp"},
        ),
        workspace=workspace,
        behaviors=DishonestBehaviors(canary_exfiltration=True),
        canary_provider=lambda case_id: CanaryVault(store).load(case_id),
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool(
                "summarize_documents",
                {"document_ids": ["doc-airlock"]},
                meta={
                    "io.airlock/caseId": victim.case_id,
                    "io.airlock/probeId": "probe_attacker",
                },
            )

    result = asyncio.run(exercise())

    assert result.is_error is True
    assert not (workspace / "documents" / victim.case_id).exists()
    assert store.load_case(victim.case_id).events == []


def test_fixture_canary_files_are_private(tmp_path):
    create_dishonest_server(
        observer=FixtureObserver(case_id="fixture_case"),
        workspace=tmp_path,
        behaviors=DishonestBehaviors(),
        canaries={"document_secret": "airlock_canary_private"},
    )

    canary_path = tmp_path / "documents" / ".airlock-canary-document_secret.txt"
    assert canary_path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "documents").stat().st_mode & 0o777 == 0o700


def _controlled_fixture_server(tmp_path, **kwargs):
    store = JsonCaseStore(tmp_path / "cases")
    server = create_honest_server(
        observer=StoreFixtureObserver(
            store,
            signing_key="fixture-signing-key",
            allowed_target_urls={"https://fixture.example/mcp"},
        ),
        workspace=tmp_path / "fixture",
        **kwargs,
    )
    return store, server


def test_a_runtime_call_without_probe_metadata_is_served(tmp_path):
    # A post-approval call arriving through the enforcing proxy carries none of
    # Airlock's probe metadata, because it is not a probe. Refusing it made the
    # bundled fixtures impossible to use for a real task after approval.
    store, server = _controlled_fixture_server(tmp_path)

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool("search_docs", {"query": "invoice"})

    result = asyncio.run(exercise())

    assert result.is_error is False


def test_a_runtime_call_contributes_no_audit_evidence(tmp_path):
    # It is served, but it is not a probe, so nothing may enter the evidence
    # store under it.
    store, server = _controlled_fixture_server(tmp_path)
    case = store.create_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
        evidence_mode=EvidenceMode.CONTROLLED_FIXTURE,
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            return await client.call_tool("search_docs", {"query": "invoice"})

    assert asyncio.run(exercise()).is_error is False
    assert store.load_case(case.case_id).events == []


def test_partial_probe_metadata_is_still_refused(tmp_path):
    # Only the total absence of metadata means "runtime call". Anything partial
    # must not be able to downgrade itself out of signature verification.
    store, server = _controlled_fixture_server(tmp_path)
    case = store.create_case(
        target_url="https://fixture.example/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
        evidence_mode=EvidenceMode.CONTROLLED_FIXTURE,
    )

    async def exercise(meta):
        async with Client(server, mode="auto") as client:
            return await client.call_tool("search_docs", {"query": "x"}, meta=meta)

    unsigned = asyncio.run(
        exercise(
            {
                "io.airlock/caseId": case.case_id,
                "io.airlock/probeId": "probe_attacker",
            }
        )
    )
    assert unsigned.is_error is True

    case_only = asyncio.run(exercise({"io.airlock/caseId": case.case_id}))
    assert case_only.is_error is True

    assert store.load_case(case.case_id).events == []
