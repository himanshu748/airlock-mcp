from __future__ import annotations

from typing import Any

from .approval import minimum_approval_tools
from .catalog import compute_catalog_digest
from .check_matrix import require_complete_check_matrix
from .models import CaseRecord, CaseStatus, DecisionChoice


class DecisionRequiredError(RuntimeError):
    pass


class CaseBlockedError(RuntimeError):
    pass


class PolicyInvariantError(ValueError):
    pass


def _require_allowed_case(case: CaseRecord) -> None:
    if case.audit_completed_at is None or not case.probes:
        raise PolicyInvariantError("a completed audit is required")
    declared = {tool.name for tool in case.declared_tools}
    if not declared or len(declared) != len(case.declared_tools):
        raise PolicyInvariantError(
            "the inventoried catalog must contain unique tools"
        )
    if case.catalog_digest != compute_catalog_digest(case.declared_tools):
        raise PolicyInvariantError("the persisted catalog digest is inconsistent")
    probed = {
        probe.tool
        for probe in case.probes
        if probe.completed and probe.accepted
    }
    if not declared <= probed:
        raise PolicyInvariantError(
            "every declared tool must have persisted probe evidence"
        )
    try:
        require_complete_check_matrix(case.declared_tools, case.checks)
    except ValueError as exc:
        raise PolicyInvariantError(
            "the persisted detector matrix is incomplete or inconsistent"
        ) from exc
    if case.decision is None:
        raise DecisionRequiredError(
            "a recorded decision is required; MCP client approval is not "
            "attested by Airlock"
        )
    if case.status != CaseStatus.SEALED_ALLOWED:
        raise CaseBlockedError("blocked cases do not produce an active connector policy")
    if not case.enforcement_active:
        raise PolicyInvariantError("proxy enforcement must be active")
    if case.proxy_url is None:
        raise PolicyInvariantError("the case has no enforcing proxy URL")
    approved = set(case.decision.approved_tools)
    approval_required = set(case.decision.approval_required_tools)
    if not approved <= declared:
        raise PolicyInvariantError(
            "approved tools must exist in the inventoried catalog"
        )
    if not approval_required <= approved:
        raise PolicyInvariantError(
            "approval-gated tools must also be enabled"
        )
    minimum_required = minimum_approval_tools(case, approved)
    if not minimum_required <= approval_required:
        raise PolicyInvariantError(
            "the decision removed a minimum approval gate"
        )
    if case.decision.choice == DecisionChoice.BLOCK:
        raise PolicyInvariantError("an allowed case cannot contain a block decision")
    if (
        case.decision.choice == DecisionChoice.APPROVE_ALL
        and approved != declared
    ):
        raise PolicyInvariantError(
            "an approve-all decision must enable the full catalog"
        )


def compile_policy(case: CaseRecord, *, connector_name: str) -> dict[str, Any]:
    _require_allowed_case(case)
    assert case.decision is not None
    declared = {tool.name for tool in case.declared_tools}
    approved = set(case.decision.approved_tools)
    return {
        "mcp_servers": [
            {
                "name": connector_name,
                "enable_tools": sorted(approved),
                "disable_tools": sorted(declared - approved),
                "require_approval_for_tools": sorted(
                    case.decision.approval_required_tools
                ),
                "preload": False,
            }
        ]
    }


def compile_connector_manifest(
    case: CaseRecord,
    *,
    connector_name: str,
    expected_proxy_url: str | None = None,
) -> dict[str, Any]:
    _require_allowed_case(case)
    if expected_proxy_url is not None and case.proxy_url != expected_proxy_url:
        raise PolicyInvariantError(
            "the persisted proxy URL does not match trusted configuration"
        )
    return {
        "manifest": {
            "type": "remote",
            "name": connector_name,
            "url": case.proxy_url,
            "description": f"Airlock-enforced connector for {case.case_id}",
        }
    }
