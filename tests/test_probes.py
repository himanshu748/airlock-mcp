from dataclasses import FrozenInstanceError

import pytest
from jsonschema import Draft202012Validator

import airlock.probes as probes_module
from airlock.models import ToolDeclaration
from airlock.probes import ProbePlanner, ProbePlanningError


def test_baseline_arguments_validate_against_common_draft_2020_12_schema_types():
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "mode": {"enum": ["brief", "complete"]},
            "version": {"const": "v1"},
            "title": {"type": "string", "default": "Quarterly report"},
            "limit": {"type": "integer", "minimum": 2},
            "threshold": {"type": "number", "minimum": 0.5},
            "include_archived": {"type": "boolean"},
            "tags": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "minItems": 2,
            },
            "options": {
                "type": "object",
                "properties": {
                    "format": {"type": "string", "enum": ["json"]},
                },
                "required": ["format"],
                "additionalProperties": False,
            },
        },
        "required": [
            "mode",
            "version",
            "title",
            "limit",
            "threshold",
            "include_archived",
            "tags",
            "options",
        ],
        "additionalProperties": False,
    }
    tool = ToolDeclaration(name="export_report", input_schema=schema)

    probes = ProbePlanner(case_budget=20, per_tool_cap=20).plan(tool)

    baseline = next(probe for probe in probes if probe.kind == "baseline")
    Draft202012Validator(schema).validate(baseline.arguments)
    assert baseline.arguments["mode"] == "brief"
    assert baseline.arguments["version"] == "v1"
    assert baseline.arguments["title"] == "Quarterly report"
    assert baseline.arguments["options"] == {"format": "json"}


def test_empty_schema_produces_valid_no_argument_baseline():
    tool = ToolDeclaration(name="healthcheck", input_schema={})

    probes = ProbePlanner(case_budget=1, per_tool_cap=1).plan(tool)

    assert probes[0].kind == "baseline"
    assert probes[0].arguments == {}
    Draft202012Validator(tool.input_schema).validate(probes[0].arguments)


def test_adversarial_probes_cover_string_boundaries_paths_and_supplied_canary():
    tool = ToolDeclaration(
        name="search_docs",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 64},
                "output_path": {"type": "string", "minLength": 1},
            },
            "required": ["query", "output_path"],
            "additionalProperties": False,
        },
    )

    probes = ProbePlanner(case_budget=30, per_tool_cap=30).plan(
        tool,
        canary="airlock_canary_7f3b",
    )

    assert any(
        probe.kind == "boundary_empty" and probe.arguments["query"] == ""
        for probe in probes
    )
    assert any(
        probe.kind == "boundary_oversized"
        and len(probe.arguments["query"]) > 64
        for probe in probes
    )
    assert any(
        probe.kind == "path_traversal"
        and probe.target == "/output_path"
        and probe.arguments["output_path"].startswith("../")
        for probe in probes
    )
    canary_probe = next(
        probe
        for probe in probes
        if probe.kind == "canary" and probe.target == "/query"
    )
    assert canary_probe.arguments["query"] == "airlock_canary_7f3b"
    assert canary_probe.supplied_canary == "airlock_canary_7f3b"


def test_nested_camel_case_file_field_gets_a_path_traversal_probe():
    tool = ToolDeclaration(
        name="save_document",
        input_schema={
            "type": "object",
            "properties": {
                "options": {
                    "type": "object",
                    "properties": {
                        "destinationFile": {"type": "string"},
                    },
                    "required": ["destinationFile"],
                    "additionalProperties": False,
                },
            },
            "required": ["options"],
            "additionalProperties": False,
        },
    )

    probes = ProbePlanner(case_budget=20, per_tool_cap=20).plan(tool)

    path_probe = next(probe for probe in probes if probe.kind == "path_traversal")
    assert path_probe.target == "/options/destinationFile"
    assert path_probe.arguments["options"]["destinationFile"] == (
        "../../airlock-canary.txt"
    )


def test_schema_drift_is_planned_only_when_the_published_schema_rejects_it():
    closed_tool = ToolDeclaration(
        name="closed_search",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    )
    open_tool = ToolDeclaration(
        name="open_search",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    )
    planner = ProbePlanner(case_budget=30, per_tool_cap=15)

    closed_probes = planner.plan(closed_tool)
    open_probes = planner.plan(open_tool)

    drift = next(probe for probe in closed_probes if probe.kind == "schema_drift")
    assert not Draft202012Validator(closed_tool.input_schema).is_valid(
        drift.arguments
    )
    assert not any(probe.kind == "schema_drift" for probe in open_probes)


def test_planning_reserves_case_budget_before_probes_can_be_executed():
    first = ToolDeclaration(
        name="first",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    )
    second = ToolDeclaration(
        name="second",
        input_schema=first.input_schema,
    )
    planner = ProbePlanner(case_budget=3, per_tool_cap=2)

    first_plan = planner.plan(first, canary="case-canary")
    second_plan = planner.plan(second, canary="case-canary")

    assert len(first_plan) == 2
    assert len(second_plan) == 1
    assert planner.planned_count == 3
    assert planner.remaining_budget == 0
    assert planner.plan(second, canary="case-canary") == ()


def test_per_tool_cap_applies_even_when_case_budget_remains():
    tool = ToolDeclaration(
        name="search_docs",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    )
    planner = ProbePlanner(case_budget=10, per_tool_cap=2)

    probes = planner.plan(tool, canary="tool-canary")

    assert len(probes) == 2
    assert planner.planned_for("search_docs") == 2
    assert planner.remaining_budget == 8
    assert planner.plan(tool, canary="tool-canary") == ()


def test_candidate_materialization_stops_at_the_probe_allowance(monkeypatch):
    tool = ToolDeclaration(
        name="wide_strings",
        input_schema={
            "type": "object",
            "properties": {
                f"field_{index}": {"type": "string"}
                for index in range(100)
            },
            "required": [f"field_{index}" for index in range(100)],
            "additionalProperties": False,
        },
    )
    original_make_probe = probes_module._make_probe
    materialized = 0

    def counting_make_probe(**kwargs):
        nonlocal materialized
        materialized += 1
        return original_make_probe(**kwargs)

    monkeypatch.setattr(probes_module, "_make_probe", counting_make_probe)

    planned = ProbePlanner(case_budget=3, per_tool_cap=3).plan(
        tool,
        canary="bounded-canary",
    )

    assert len(planned) == 3
    assert materialized == 3


def test_plans_and_probe_ids_are_deterministic_and_immutable():
    tool = ToolDeclaration(
        name="get_document",
        input_schema={
            "type": "object",
            "properties": {"document_id": {"type": "string"}},
            "required": ["document_id"],
            "additionalProperties": False,
        },
    )

    first = ProbePlanner(case_budget=10, per_tool_cap=10).plan(
        tool, canary="stable-canary"
    )
    second = ProbePlanner(case_budget=10, per_tool_cap=10).plan(
        tool, canary="stable-canary"
    )

    assert first == second
    assert len({probe.probe_id for probe in first}) == len(first)
    assert all(probe.probe_id.startswith("probe_") for probe in first)
    with pytest.raises(FrozenInstanceError):
        first[0].kind = "changed"


@pytest.mark.parametrize(
    ("case_budget", "per_tool_cap"),
    [(-1, 1), (1, -1), (True, 1), (1, False)],
)
def test_invalid_budgets_are_rejected(case_budget, per_tool_cap):
    with pytest.raises(ValueError):
        ProbePlanner(case_budget=case_budget, per_tool_cap=per_tool_cap)


def test_hostile_array_minimum_is_rejected_before_generation():
    tool = ToolDeclaration(
        name="hostile_array",
        input_schema={
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 100_000_000,
                }
            },
            "required": ["items"],
        },
    )

    with pytest.raises(ProbePlanningError, match="array generation limit"):
        ProbePlanner(case_budget=1, per_tool_cap=1).plan(tool)


def test_excessive_schema_depth_and_property_count_are_rejected():
    nested = {"type": "string"}
    for index in range(40):
        nested = {
            "type": "object",
            "properties": {f"level_{index}": nested},
            "required": [f"level_{index}"],
        }
    too_many_properties = {
        "type": "object",
        "properties": {
            f"field_{index}": {"type": "string"}
            for index in range(300)
        },
    }

    with pytest.raises(ProbePlanningError, match="depth limit"):
        ProbePlanner(case_budget=1, per_tool_cap=1).plan(
            ToolDeclaration(name="deep", input_schema=nested)
        )
    with pytest.raises(ProbePlanningError, match="property limit"):
        ProbePlanner(case_budget=1, per_tool_cap=1).plan(
            ToolDeclaration(name="wide", input_schema=too_many_properties)
        )


@pytest.mark.parametrize(
    "pattern",
    [
        "^(a+)+$",
        "(a|aa)+b",
        "^[a-z]+$",
        123,
    ],
)
def test_every_json_schema_pattern_is_rejected_before_generation(pattern):
    tool = ToolDeclaration(
        name="regex_trap",
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "pattern": pattern,
                }
            },
            "required": ["query"],
        },
    )

    with pytest.raises(ProbePlanningError, match="pattern keyword"):
        ProbePlanner(case_budget=1, per_tool_cap=1).plan(tool)


def test_property_named_pattern_is_not_treated_as_schema_keyword():
    tool = ToolDeclaration(
        name="describe_pattern",
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    )

    probes = ProbePlanner(case_budget=1, per_tool_cap=1).plan(tool)

    assert probes[0].arguments == {"pattern": "airlock"}
