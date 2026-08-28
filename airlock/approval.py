from __future__ import annotations

from collections.abc import Iterable

from .models import CaseRecord, FindingStatus

# A check whose sensor was configured but produced nothing is a surprise and
# must be gated. A check no sensor in this case can observe is a disclosed
# limitation of the evidence mode, recorded in the report rather than gated.
_CAPABILITY_ABSENT_SENSOR = "capability_absent"


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
    unobserved = {
        finding.tool
        for finding in case.checks
        if finding.status == FindingStatus.SENSOR_FAILED
        or (
            finding.status == FindingStatus.NOT_TESTED
            and finding.sensor != _CAPABILITY_ABSENT_SENSOR
        )
    }
    return approved & (declared_sensitive | observed_findings | unobserved)


__all__ = ["minimum_approval_tools"]
