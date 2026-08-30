import json
import re
from pathlib import Path

import pytest

from airlock.control import CONTROL_TOOL_ANNOTATIONS

CONTROL_SOURCE = Path(__file__).parents[1] / "airlock" / "control.py"


def _agent_spec() -> dict:
    spec_path = Path(__file__).parents[1] / "configs" / "trueforge-agent.json"
    return json.loads(spec_path.read_text(encoding="utf-8"))


def _gated_tools() -> set[str]:
    control = next(
        server
        for server in _agent_spec()["mcp_servers"]
        if server["name"] == "airlock-control"
    )
    return set(control["require_approval_for_tools"])


def test_the_annotation_map_covers_every_registered_control_tool():
    """Without this, a new tool could skip the map and dodge the gate check."""
    registered = set(
        re.findall(r'@server\.tool\(\s*\n\s*name="([a-z_]+)"', CONTROL_SOURCE.read_text())
    )

    assert registered, "no control tools were found in the source"
    assert registered == set(CONTROL_TOOL_ANNOTATIONS), (
        "control tool map is out of step with the server: "
        f"{sorted(registered ^ set(CONTROL_TOOL_ANNOTATIONS))}"
    )


def test_every_destructive_control_tool_is_gated_in_the_agent_spec():
    destructive = {
        name
        for name, annotations in CONTROL_TOOL_ANNOTATIONS.items()
        if annotations.destructive_hint
    }

    assert destructive, "no destructive control tools were discovered"
    assert destructive <= _gated_tools(), (
        "destructive but not gated: "
        f"{sorted(destructive - _gated_tools())}"
    )


def test_the_gate_names_no_tool_that_does_not_exist():
    gated = _gated_tools()
    known = set(CONTROL_TOOL_ANNOTATIONS)

    assert gated <= known, f"gate names unknown tools: {sorted(gated - known)}"


@pytest.mark.parametrize("tool", ["probe_tool", "seal_case", "emit_policy"])
def test_the_three_publishing_tools_stay_gated(tool: str):
    assert tool in _gated_tools()


def test_no_decorator_supplies_annotations_outside_the_map():
    """A literal annotation on a decorator is how the two drift apart."""
    source = CONTROL_SOURCE.read_text()
    literal = re.findall(r"annotations=(_[A-Z_]+),", source)

    assert not literal, (
        "these tools annotate outside CONTROL_TOOL_ANNOTATIONS and can drift "
        f"from what the gate test checks: {sorted(set(literal))}"
    )
