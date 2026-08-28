from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence, Tuple, Union

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .models import ToolDeclaration


_MAX_GENERATED_STRING_LENGTH = 8_192
_MAX_GENERATED_ARRAY_ITEMS = 32
_MAX_GENERATED_ARGUMENT_BYTES = 65_536
_MAX_SCHEMA_DEPTH = 32
_MAX_SCHEMA_NODES = 4_096
_MAX_SCHEMA_PROPERTIES = 256
_MAX_SCHEMA_LIST_ITEMS = 256
_MAX_PLANNED_PROBES_PER_TOOL = 24
_OVERSIZED_STRING_LENGTH = 4_096
_SCHEMA_DRIFT_KEY = "_airlock_undeclared"
_PATH_FIELD_PATTERN = re.compile(
    r"(?:^|_)(?:path|file|filename|filepath|directory|dir|folder|root|"
    r"destination|output|source|target)(?:_|$)",
    re.IGNORECASE,
)
class ProbePlanningError(ValueError):
    """Raised when Airlock cannot create a valid baseline for a tool schema."""


@dataclass(frozen=True)
class PlannedProbe:
    probe_id: str
    tool: str
    kind: str
    arguments: dict[str, Any]
    target: Optional[str] = None
    supplied_canary: Optional[str] = None


class ProbePlanner:
    def __init__(self, *, case_budget: int, per_tool_cap: int) -> None:
        self._validate_budget("case_budget", case_budget)
        self._validate_budget("per_tool_cap", per_tool_cap)
        self.case_budget = case_budget
        self.per_tool_cap = per_tool_cap
        self._planned_ids: set[str] = set()
        self._planned_by_tool: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _validate_budget(name: str, value: int) -> None:
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")

    @property
    def planned_count(self) -> int:
        with self._lock:
            return len(self._planned_ids)

    @property
    def remaining_budget(self) -> int:
        with self._lock:
            return max(0, self.case_budget - len(self._planned_ids))

    def planned_for(self, tool_name: str) -> int:
        with self._lock:
            return self._planned_by_tool.get(tool_name, 0)

    def plan(
        self,
        tool: ToolDeclaration,
        *,
        canary: Optional[str] = None,
    ) -> Tuple[PlannedProbe, ...]:
        if canary is not None and not isinstance(canary, str):
            raise ValueError("canary must be a string")

        with self._lock:
            allowance = min(
                self.case_budget - len(self._planned_ids),
                self.per_tool_cap - self._planned_by_tool.get(tool.name, 0),
                _MAX_PLANNED_PROBES_PER_TOOL,
            )
            if allowance <= 0:
                return ()

        candidates = _build_candidates(
            tool,
            canary=canary,
            max_candidates=allowance,
        )

        with self._lock:
            case_remaining = self.case_budget - len(self._planned_ids)
            tool_remaining = (
                self.per_tool_cap - self._planned_by_tool.get(tool.name, 0)
            )
            allowance = max(0, min(case_remaining, tool_remaining))
            if allowance == 0:
                return ()

            selected: list[PlannedProbe] = []
            for candidate in candidates:
                if candidate.probe_id in self._planned_ids:
                    continue
                selected.append(candidate)
                if len(selected) == allowance:
                    break

            self._planned_ids.update(probe.probe_id for probe in selected)
            self._planned_by_tool[tool.name] = (
                self._planned_by_tool.get(tool.name, 0) + len(selected)
            )
            return tuple(selected)


def _build_candidates(
    tool: ToolDeclaration,
    *,
    canary: Optional[str],
    max_candidates: int,
) -> list[PlannedProbe]:
    _validate_schema_limits(tool.input_schema)
    schema = copy.deepcopy(tool.input_schema)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ProbePlanningError(
            f"{tool.name} published an invalid JSON Schema: {exc.message}"
        ) from exc

    validator = Draft202012Validator(schema)
    baseline = _generate_value(schema)
    if not isinstance(baseline, dict):
        if validator.is_valid({}):
            baseline = {}
        else:
            raise ProbePlanningError(
                f"{tool.name} input schema must describe an object of tool arguments"
            )

    errors = sorted(validator.iter_errors(baseline), key=lambda error: list(error.path))
    if errors:
        raise ProbePlanningError(
            f"Could not generate valid baseline arguments for {tool.name}: "
            f"{errors[0].message}"
        )
    baseline_bytes = len(
        json.dumps(
            baseline,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    if baseline_bytes > _MAX_GENERATED_ARGUMENT_BYTES:
        raise ProbePlanningError(
            "Generated arguments exceed the Airlock payload limit"
        )

    candidates = [
        _make_probe(
            tool=tool.name,
            kind="baseline",
            arguments=baseline,
        )
    ]
    if len(candidates) >= max_candidates:
        return candidates

    drift_arguments = copy.deepcopy(baseline)
    drift_key = _unused_drift_key(drift_arguments)
    drift_arguments[drift_key] = True
    if not validator.is_valid(drift_arguments):
        candidates.append(
            _make_probe(
                tool=tool.name,
                kind="schema_drift",
                arguments=drift_arguments,
                target=_json_pointer((drift_key,)),
            )
        )
        if len(candidates) >= max_candidates:
            return candidates

    if canary is not None:
        for path, _subschema in _iter_string_targets(schema, baseline):
            candidates.append(
                _make_probe(
                    tool=tool.name,
                    kind="canary",
                    arguments=_replace_at_path(baseline, path, canary),
                    target=_json_pointer(path),
                    supplied_canary=canary,
                )
            )
            if len(candidates) >= max_candidates:
                return candidates

    for path, _subschema in _iter_string_targets(schema, baseline):
        if _is_path_field(path):
            candidates.append(
                _make_probe(
                    tool=tool.name,
                    kind="path_traversal",
                    arguments=_replace_at_path(
                        baseline,
                        path,
                        "../../airlock-canary.txt",
                    ),
                    target=_json_pointer(path),
                )
            )
            if len(candidates) >= max_candidates:
                return candidates

    for path, subschema in _iter_string_targets(schema, baseline):
        candidates.append(
            _make_probe(
                tool=tool.name,
                kind="boundary_empty",
                arguments=_replace_at_path(baseline, path, ""),
                target=_json_pointer(path),
            )
        )
        if len(candidates) >= max_candidates:
            return candidates
        candidates.append(
            _make_probe(
                tool=tool.name,
                kind="boundary_oversized",
                arguments=_replace_at_path(
                    baseline,
                    path,
                    _oversized_string(subschema),
                ),
                target=_json_pointer(path),
            )
        )
        if len(candidates) >= max_candidates:
            return candidates

    return candidates


def _make_probe(
    *,
    tool: str,
    kind: str,
    arguments: dict[str, Any],
    target: Optional[str] = None,
    supplied_canary: Optional[str] = None,
) -> PlannedProbe:
    arguments_copy = copy.deepcopy(arguments)
    identity = json.dumps(
        {
            "arguments": arguments_copy,
            "kind": kind,
            "target": target,
            "tool": tool,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return PlannedProbe(
        probe_id=f"probe_{digest}",
        tool=tool,
        kind=kind,
        arguments=arguments_copy,
        target=target,
        supplied_canary=supplied_canary,
    )


def _generate_value(schema: Any, *, salt: int = 0) -> Any:
    if schema is True:
        return "airlock" if salt == 0 else f"airlock-{salt}"
    if schema is False or not isinstance(schema, dict):
        raise ProbePlanningError("Schema does not permit a generated value")

    preferred = []
    if "default" in schema:
        preferred.append(schema["default"])
    if "const" in schema:
        preferred.append(schema["const"])
    preferred.extend(schema.get("enum", []))
    for value in preferred:
        candidate = copy.deepcopy(value)
        if _is_valid_for_subschema(schema, candidate):
            return candidate

    candidate_types = _candidate_types(schema)
    for candidate_type in candidate_types:
        try:
            if candidate_type == "object":
                candidates = _object_candidates(schema)
            elif candidate_type == "array":
                candidates = [_generate_array(schema)]
            elif candidate_type == "string":
                candidates = _string_candidates(schema, salt=salt)
            elif candidate_type == "integer":
                candidates = _number_candidates(schema, integer=True, salt=salt)
            elif candidate_type == "number":
                candidates = _number_candidates(schema, integer=False, salt=salt)
            elif candidate_type == "boolean":
                candidates = [False, True]
            elif candidate_type == "null":
                candidates = [None]
            else:
                continue
        except ProbePlanningError:
            continue
        for candidate in candidates:
            if _is_valid_for_subschema(schema, candidate):
                return candidate

    raise ProbePlanningError("Schema does not permit a supported deterministic value")


def _candidate_types(schema: dict[str, Any]) -> list[str]:
    declared_type = schema.get("type")
    if isinstance(declared_type, str):
        return [declared_type]
    if isinstance(declared_type, list):
        non_null = [item for item in declared_type if item != "null"]
        return non_null + (["null"] if "null" in declared_type else [])
    if "properties" in schema or "required" in schema:
        return ["object"]
    if "items" in schema or "prefixItems" in schema:
        return ["array"]
    return ["string", "object", "array", "integer", "number", "boolean", "null"]


def _object_candidates(schema: dict[str, Any]) -> list[dict[str, Any]]:
    raw_properties = schema.get("properties", {})
    properties = raw_properties if isinstance(raw_properties, dict) else {}
    required = set(schema.get("required", []))
    complete: dict[str, Any] = {}
    required_only: dict[str, Any] = {}

    for name in sorted(properties):
        property_schema = properties[name]
        try:
            value = _generate_value(property_schema)
        except ProbePlanningError:
            if name in required:
                raise
            continue
        complete[name] = value
        if (
            name in required
            or (isinstance(property_schema, dict) and "default" in property_schema)
            or (isinstance(property_schema, dict) and "const" in property_schema)
        ):
            required_only[name] = copy.deepcopy(value)

    missing = required.difference(complete)
    if missing:
        names = ", ".join(sorted(str(name) for name in missing))
        raise ProbePlanningError(f"Could not generate required properties: {names}")

    candidates = [complete]
    if required_only != complete:
        candidates.append(required_only)
    return candidates


def _generate_array(schema: dict[str, Any]) -> list[Any]:
    min_items = schema.get("minItems", 0)
    max_items = schema.get("maxItems")
    if type(min_items) is not int or min_items < 0:
        raise ProbePlanningError("minItems must be a non-negative integer")
    if max_items is not None and (type(max_items) is not int or max_items < min_items):
        raise ProbePlanningError("Array bounds do not permit a generated value")
    if min_items > _MAX_GENERATED_ARRAY_ITEMS:
        raise ProbePlanningError(
            "minItems exceeds the Airlock array generation limit"
        )

    prefix_items = schema.get("prefixItems", [])
    if not isinstance(prefix_items, list):
        prefix_items = []
    target_length = min_items
    if target_length == 0 and (prefix_items or schema.get("items", True) is not False):
        target_length = 1
    if max_items is not None:
        target_length = min(target_length, max_items)
    if target_length > _MAX_GENERATED_ARRAY_ITEMS:
        raise ProbePlanningError(
            "Array target exceeds the Airlock array generation limit"
        )

    values: list[Any] = []
    item_schema = schema.get("items", True)
    for index in range(target_length):
        active_schema = prefix_items[index] if index < len(prefix_items) else item_schema
        values.append(_generate_value(active_schema, salt=index))
    return values


def _string_candidates(schema: dict[str, Any], *, salt: int) -> list[str]:
    min_length = schema.get("minLength", 0)
    max_length = schema.get("maxLength")
    if type(min_length) is not int or min_length < 0:
        raise ProbePlanningError("minLength must be a non-negative integer")
    if max_length is not None and (
        type(max_length) is not int or max_length < min_length
    ):
        raise ProbePlanningError("String bounds do not permit a generated value")
    if min_length > _MAX_GENERATED_STRING_LENGTH:
        raise ProbePlanningError("Required string is larger than the generation limit")

    seeds = [
        "airlock" if salt == 0 else f"airlock-{salt}",
        "0",
        "a",
        "test@example.com",
        "https://example.invalid/",
        "/workspace/airlock.txt",
        "00000000-0000-4000-8000-000000000000",
        "",
    ]
    candidates: list[str] = []
    for seed in seeds:
        candidate = seed
        if len(candidate) < min_length:
            candidate += "a" * (min_length - len(candidate))
        if max_length is not None:
            candidate = candidate[:max_length]
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _number_candidates(
    schema: dict[str, Any],
    *,
    integer: bool,
    salt: int,
) -> list[Union[int, float]]:
    candidates: list[Union[int, float]] = [salt, 0, 1, -1]
    minimum = schema.get("minimum")
    exclusive_minimum = schema.get("exclusiveMinimum")
    maximum = schema.get("maximum")
    exclusive_maximum = schema.get("exclusiveMaximum")

    for value in (minimum, maximum):
        if _is_number(value):
            candidates.append(value)
    if _is_number(exclusive_minimum):
        candidates.extend([exclusive_minimum + 1, exclusive_minimum + 0.5])
    if _is_number(exclusive_maximum):
        candidates.extend([exclusive_maximum - 1, exclusive_maximum - 0.5])

    lower = exclusive_minimum if _is_number(exclusive_minimum) else minimum
    upper = exclusive_maximum if _is_number(exclusive_maximum) else maximum
    if _is_number(lower) and _is_number(upper):
        candidates.append((lower + upper) / 2)

    multiple = schema.get("multipleOf")
    if _is_number(multiple) and multiple > 0:
        candidates.extend([multiple, -multiple])
        if _is_number(lower):
            multiplier = math.ceil(lower / multiple)
            candidates.extend([multiplier * multiple, (multiplier + 1) * multiple])

    normalized: list[Union[int, float]] = []
    for candidate in candidates:
        if not _is_number(candidate):
            continue
        if integer:
            if isinstance(candidate, float) and not candidate.is_integer():
                continue
            candidate = int(candidate)
        elif isinstance(candidate, int):
            candidate = float(candidate)
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _is_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _validate_schema_limits(schema: Any) -> None:
    stack: list[tuple[Any, int]] = [(schema, 0)]
    seen_container_ids: set[int] = set()
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_SCHEMA_NODES:
            raise ProbePlanningError("JSON Schema exceeds the Airlock node limit")
        if depth > _MAX_SCHEMA_DEPTH:
            raise ProbePlanningError("JSON Schema exceeds the Airlock depth limit")

        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in seen_container_ids:
                raise ProbePlanningError("JSON Schema contains a recursive object")
            seen_container_ids.add(identity)

        if isinstance(value, list):
            if len(value) > _MAX_SCHEMA_LIST_ITEMS:
                raise ProbePlanningError(
                    "JSON Schema exceeds the Airlock list-size limit"
                )
            stack.extend((item, depth + 1) for item in value)
            continue
        if not isinstance(value, dict):
            continue

        if "$ref" in value or "$dynamicRef" in value:
            raise ProbePlanningError(
                "JSON Schema references are outside the bounded probe profile"
            )
        properties = value.get("properties")
        if isinstance(properties, dict) and len(properties) > _MAX_SCHEMA_PROPERTIES:
            raise ProbePlanningError(
                "JSON Schema exceeds the Airlock property limit"
            )
        pattern_properties = value.get("patternProperties")
        if isinstance(pattern_properties, dict) and pattern_properties:
            raise ProbePlanningError(
                "patternProperties are outside the bounded probe profile"
            )
        min_items = value.get("minItems")
        if type(min_items) is int and min_items > _MAX_GENERATED_ARRAY_ITEMS:
            raise ProbePlanningError(
                "minItems exceeds the Airlock array generation limit"
            )
        stack.extend((item, depth + 1) for item in value.values())

    _reject_pattern_keywords(schema)


def _reject_pattern_keywords(schema: Any) -> None:
    direct_subschema_keywords = (
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    )
    subschema_list_keywords = ("allOf", "anyOf", "oneOf", "prefixItems")
    subschema_map_keywords = (
        "$defs",
        "definitions",
        "dependentSchemas",
        "patternProperties",
        "properties",
    )
    stack = [schema]
    seen_schema_ids: set[int] = set()

    while stack:
        candidate = stack.pop()
        if not isinstance(candidate, dict):
            continue
        identity = id(candidate)
        if identity in seen_schema_ids:
            continue
        seen_schema_ids.add(identity)

        if "pattern" in candidate:
            raise ProbePlanningError(
                "JSON Schema pattern keyword is outside the bounded probe profile"
            )

        stack.extend(candidate.get(keyword) for keyword in direct_subschema_keywords)
        for keyword in subschema_list_keywords:
            subschemas = candidate.get(keyword)
            if isinstance(subschemas, list):
                stack.extend(subschemas)
        for keyword in subschema_map_keywords:
            subschemas = candidate.get(keyword)
            if isinstance(subschemas, dict):
                stack.extend(subschemas.values())

        dependencies = candidate.get("dependencies")
        if isinstance(dependencies, dict):
            stack.extend(
                dependency
                for dependency in dependencies.values()
                if isinstance(dependency, dict)
            )


def _is_valid_for_subschema(schema: dict[str, Any], candidate: Any) -> bool:
    try:
        return Draft202012Validator(schema).is_valid(candidate)
    except Exception:
        return False


PathPart = Union[str, int]


def _iter_string_targets(
    schema: Any,
    instance: Any,
    path: Tuple[PathPart, ...] = (),
) -> Iterable[Tuple[Tuple[PathPart, ...], dict[str, Any]]]:
    if not isinstance(schema, dict):
        return
    if _schema_accepts_string(schema) and isinstance(instance, str):
        yield path, schema
        return

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return
        for name in sorted(instance):
            if name in properties:
                yield from _iter_string_targets(
                    properties[name],
                    instance[name],
                    path + (name,),
                )
    elif isinstance(instance, list):
        prefix_items = schema.get("prefixItems", [])
        if not isinstance(prefix_items, list):
            prefix_items = []
        item_schema = schema.get("items", True)
        for index, value in enumerate(instance):
            active_schema = prefix_items[index] if index < len(prefix_items) else item_schema
            yield from _iter_string_targets(
                active_schema,
                value,
                path + (index,),
            )


def _schema_accepts_string(schema: dict[str, Any]) -> bool:
    declared_type = schema.get("type")
    if declared_type == "string":
        return True
    if isinstance(declared_type, list) and "string" in declared_type:
        return True
    if "const" in schema and isinstance(schema["const"], str):
        return True
    enum_values = schema.get("enum")
    return isinstance(enum_values, list) and any(
        isinstance(value, str) for value in enum_values
    )


def _replace_at_path(
    baseline: dict[str, Any],
    path: Sequence[PathPart],
    value: str,
) -> dict[str, Any]:
    result = copy.deepcopy(baseline)
    cursor: Any = result
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    return result


def _json_pointer(path: Sequence[PathPart]) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in path]
    return "/" + "/".join(encoded)


def _is_path_field(path: Sequence[PathPart]) -> bool:
    field_names = [part for part in path if isinstance(part, str)]
    if not field_names:
        return False
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", field_names[-1]).replace("-", "_")
    return bool(_PATH_FIELD_PATTERN.search(normalized))


def _oversized_string(schema: dict[str, Any]) -> str:
    max_length = schema.get("maxLength")
    target_length = _OVERSIZED_STRING_LENGTH
    if type(max_length) is int and max_length < _MAX_GENERATED_STRING_LENGTH:
        target_length = max(target_length, max_length + 1)
    return "A" * min(target_length, _MAX_GENERATED_STRING_LENGTH)


def _unused_drift_key(arguments: dict[str, Any]) -> str:
    candidate = _SCHEMA_DRIFT_KEY
    suffix = 1
    while candidate in arguments:
        candidate = f"{_SCHEMA_DRIFT_KEY}_{suffix}"
        suffix += 1
    return candidate
