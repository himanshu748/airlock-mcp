from airlock.approval import minimum_approval_tools
from airlock.models import (
    CheckName,
    EvidenceStrength,
    Finding,
    FindingStatus,
    ToolDeclaration,
)
from types import SimpleNamespace


def _case(checks):
    return SimpleNamespace(
        declared_tools=[
            ToolDeclaration(name="search_docs", annotations={"readOnlyHint": True}),
        ],
        checks=checks,
    )


def _check(status, sensor):
    return Finding(
        tool="search_docs",
        check=CheckName.UNDECLARED_EGRESS,
        status=status,
        evidence_strength=EvidenceStrength.NONE,
        sensor=sensor,
        explanation="fixture",
    )


def test_a_clean_read_only_tool_needs_no_forced_approval_gate():
    case = _case([_check(FindingStatus.NO_FINDING_OBSERVED, "aggregate")])

    assert minimum_approval_tools(case, ["search_docs"]) == set()


def test_a_check_no_sensor_can_observe_does_not_force_an_approval_gate():
    case = _case([_check(FindingStatus.NOT_TESTED, "capability_absent")])

    assert minimum_approval_tools(case, ["search_docs"]) == set()


def test_a_configured_sensor_with_no_evidence_forces_an_approval_gate():
    case = _case([_check(FindingStatus.NOT_TESTED, "evidence_missing")])

    assert minimum_approval_tools(case, ["search_docs"]) == {"search_docs"}


def test_a_failed_sensor_forces_an_approval_gate():
    case = _case([_check(FindingStatus.SENSOR_FAILED, "mcp_transcript")])

    assert minimum_approval_tools(case, ["search_docs"]) == {"search_docs"}


def test_an_unapproved_tool_is_never_added_to_the_approval_gate():
    case = _case([_check(FindingStatus.SENSOR_FAILED, "mcp_transcript")])

    assert minimum_approval_tools(case, []) == set()
