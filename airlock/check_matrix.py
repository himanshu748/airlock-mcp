from __future__ import annotations

from collections.abc import Iterable

from .models import CheckName, Finding, ToolDeclaration


def require_complete_check_matrix(
    declarations: Iterable[ToolDeclaration],
    checks: Iterable[Finding],
) -> None:
    declared_names = {declaration.name for declaration in declarations}
    expected = {
        (tool_name, check)
        for tool_name in declared_names
        for check in CheckName
    }
    observed = [(finding.tool, finding.check) for finding in checks]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError(
            "checks must contain exactly one result for every inventoried "
            "tool and detector"
        )


__all__ = ["require_complete_check_matrix"]
