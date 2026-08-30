import asyncio
import json
from pathlib import Path

import pytest
from mcp import Client

from airlock.case_service import CaseService
from airlock.control import CONTROL_TOOL_ANNOTATIONS, create_control_server
from airlock.store import JsonCaseStore
from tests.test_control import StubAuditExecutor


def _registered_tools(tmp_path):
    """Ask the built server what it registered.

    Reading the decorators out of the source with a regex missed any tool that
    spelled its registration differently, and a missed tool passed every check
    while going ungated. The server itself cannot be spelled around.
    """
    store = JsonCaseStore(tmp_path / "cases")
    service = CaseService(
        store,
        public_base_url="https://airlock.example",
        target_resolver=lambda hostname: ["93.184.216.34"],
    )
    server = create_control_server(
        store=store,
        case_service=service,
        audit_executor=StubAuditExecutor(service),
    )

    async def exercise():
        async with Client(server, mode="auto") as client:
            result = await client.list_tools()
            return getattr(result, "tools", result)

    return asyncio.run(exercise())


def _gated_tools() -> set[str]:
    spec_path = Path(__file__).parents[1] / "configs" / "trueforge-agent.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    control = next(
        server
        for server in spec["mcp_servers"]
        if server["name"] == "airlock-control"
    )
    return set(control["require_approval_for_tools"])


def _is_destructive(tool) -> bool:
    annotations = tool.annotations
    return bool(
        getattr(annotations, "destructiveHint", None)
        or getattr(annotations, "destructive_hint", None)
    )


def test_every_destructive_control_tool_is_gated_in_the_agent_spec(tmp_path):
    tools = _registered_tools(tmp_path)
    destructive = {tool.name for tool in tools if _is_destructive(tool)}

    assert destructive, "no destructive control tools were discovered"
    assert destructive <= _gated_tools(), (
        "destructive but not gated: " f"{sorted(destructive - _gated_tools())}"
    )


def test_the_gate_names_no_tool_that_does_not_exist(tmp_path):
    registered = {tool.name for tool in _registered_tools(tmp_path)}
    gated = _gated_tools()

    assert gated <= registered, (
        f"gate names unknown tools: {sorted(gated - registered)}"
    )


def test_the_annotation_map_matches_what_the_server_registers(tmp_path):
    """The decorators read from this map, so a mismatch means it drifted."""
    tools = _registered_tools(tmp_path)

    assert {tool.name for tool in tools} == set(CONTROL_TOOL_ANNOTATIONS)
    for tool in tools:
        assert _is_destructive(tool) == bool(
            CONTROL_TOOL_ANNOTATIONS[tool.name].destructive_hint
        ), f"{tool.name} is annotated differently than the map claims"


@pytest.mark.parametrize("tool", ["probe_tool", "seal_case", "emit_policy"])
def test_the_three_publishing_tools_stay_gated(tool: str):
    assert tool in _gated_tools()


@pytest.mark.parametrize("tool", ["probe_tool", "seal_case", "emit_policy"])
def test_the_three_publishing_tools_stay_destructive(tmp_path, tool: str):
    """Gating follows the annotation, so relaxing one silently ungates a tool.

    Without this the annotation could be downgraded and every other check here
    would still pass: the tool stops counting as destructive, so nothing
    requires it to be gated any more.
    """
    registered = {item.name: item for item in _registered_tools(tmp_path)}

    assert _is_destructive(registered[tool]), (
        f"{tool} exercises a live server, seals a case or publishes a policy "
        "and must stay annotated destructive"
    )
