from __future__ import annotations

from collections.abc import Iterable

from .models import CaseRecord, FindingStatus


def minimum_approval_tools(
    case: CaseRecord,
    approved_tools: Iterable[str],
) -> set[str]:
    approved = set(approved_tools)
    declared_sensitive = {
        tool.name
        for tool in case.declared_tools
        if tool.annotations.get("readOnlyHint") is not True
        or tool.annotations.get("destructiveHint") is True
    }
    observed_findings = {
        finding.tool
        for finding in case.checks
        if finding.status == FindingStatus.FINDING
    }
    return approved & (declared_sensitive | observed_findings)


__all__ = ["minimum_approval_tools"]
