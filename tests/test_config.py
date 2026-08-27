import json
from pathlib import Path


def test_agent_spec_approval_gates_every_side_effecting_control_tool():
    spec_path = Path(__file__).parents[1] / "configs" / "trueforge-agent.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    control = next(
        server
        for server in spec["mcp_servers"]
        if server["name"] == "airlock-control"
    )

    assert set(control["require_approval_for_tools"]) >= {
        "probe_tool",
        "seal_case",
        "emit_policy",
    }
