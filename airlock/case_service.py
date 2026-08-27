from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from .approval import minimum_approval_tools
from .catalog import compute_catalog_digest
from .check_matrix import require_complete_check_matrix
from .models import (
    CaseRecord,
    CaseStatus,
    Decision,
    DecisionChoice,
    DeclaredScope,
    EvidenceMode,
    Finding,
    ObservationCapabilities,
    TargetBinding,
    ToolDeclaration,
)
from .store import JsonCaseStore
from .target_policy import TargetValidationError, validate_target_url


def _system_resolver(hostname: str) -> list[str]:
    return sorted(
        {
            address[4][0]
            for address in socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        }
    )


class CaseService:
    def __init__(
        self,
        store: JsonCaseStore,
        *,
        public_base_url: str,
        target_resolver: Callable[[str], Iterable[str]] = _system_resolver,
        allow_local_targets: bool = False,
        allowed_target_hostnames: Iterable[str] | None = None,
        credential_target_urls: Iterable[str] | None = None,
    ) -> None:
        self.store = store
        self.public_base_url = public_base_url.rstrip("/")
        self.target_resolver = target_resolver
        self.allow_local_targets = allow_local_targets
        self.allowed_target_hostnames = allowed_target_hostnames
        self.credential_target_urls = (
            frozenset(credential_target_urls)
            if credential_target_urls is not None
            else None
        )

    def open_case(
        self,
        *,
        target_url: str,
        declared_scope: DeclaredScope,
        evidence_mode: EvidenceMode,
        capabilities: ObservationCapabilities,
    ) -> CaseRecord:
        self._require_credential_target_scope(target_url)
        validated = validate_target_url(
            target_url,
            resolver=self.target_resolver,
            allow_local=self.allow_local_targets,
            allowed_hostnames=self.allowed_target_hostnames,
        )
        case = self.store.create_case(
            target_url=target_url,
            declared_scope=declared_scope,
            observation_capabilities=capabilities,
            evidence_mode=evidence_mode,
            target_binding=TargetBinding(
                scheme=validated.scheme,
                hostname=validated.hostname,
                port=validated.port,
                resolved_ips=list(validated.resolved_ips),
            ),
        )
        case = case.model_copy(
            update={
                "proxy_url": (
                    f"{self.public_base_url}/cases/{case.case_id}/mcp"
                )
            }
        )
        self.store.save_case(case)
        return case

    def revalidate_target(self, case_id: str) -> TargetBinding:
        case = self.store.load_case(case_id)
        self._require_credential_target_scope(case.target_url)
        if case.target_binding is None:
            raise TargetValidationError("case has no validated target binding")
        validated = validate_target_url(
            case.target_url,
            resolver=self.target_resolver,
            allow_local=self.allow_local_targets,
            allowed_hostnames=self.allowed_target_hostnames,
        )
        current_ips = set(validated.resolved_ips)
        approved_ips = set(case.target_binding.resolved_ips)
        if current_ips != approved_ips:
            raise TargetValidationError("target DNS binding changed after case creation")
        return case.target_binding

    def _require_credential_target_scope(self, target_url: str) -> None:
        if (
            self.credential_target_urls is not None
            and target_url not in self.credential_target_urls
        ):
            raise TargetValidationError(
                "target URL is outside the exact scope of configured target credentials"
            )

    def record_inventory(
        self,
        case_id: str,
        *,
        declarations: list[ToolDeclaration],
        protocol_version: str,
        auth_context_fingerprint: str,
    ) -> CaseRecord:
        case = self.store.load_case(case_id)
        ordered = sorted(declarations, key=lambda item: item.name)
        if not ordered:
            raise ValueError("tool inventory must contain at least one tool")
        names = [item.name for item in ordered]
        if len(names) != len(set(names)):
            raise ValueError("inventoried tool names must be unique")
        catalog_digest = compute_catalog_digest(ordered)
        updated = case.model_copy(
            update={
                "status": CaseStatus.INVENTORIED,
                "declared_tools": ordered,
                "protocol_version": protocol_version,
                "auth_context_fingerprint": auth_context_fingerprint,
                "catalog_digest": catalog_digest,
            }
        )
        self.store.save_case(updated)
        return updated

    def mark_awaiting_decision(self, case_id: str) -> CaseRecord:
        case = self.store.load_case(case_id)
        if case.audit_completed_at is None:
            raise ValueError("case has no completed audit")
        updated = case.model_copy(update={"status": CaseStatus.AWAITING_DECISION})
        self.store.save_case(updated)
        return updated

    def start_probing(self, case_id: str) -> CaseRecord:
        case = self.store.load_case(case_id)
        if case.status not in {CaseStatus.INVENTORIED, CaseStatus.PROBING}:
            raise ValueError("case must be inventoried before probing")
        updated = case.model_copy(update={"status": CaseStatus.PROBING})
        self.store.save_case(updated)
        return updated

    def configure_probe_budget(self, case_id: str, *, probe_budget: int) -> CaseRecord:
        if type(probe_budget) is not int or probe_budget <= 0:
            raise ValueError("probe budget must be a positive integer")
        case = self.store.load_case(case_id)
        if case.status != CaseStatus.PROBING:
            raise ValueError("case must be probing before a budget is configured")
        if case.probe_budget != 0:
            return case
        return self.store.configure_probe_budget(
            case_id,
            probe_budget=probe_budget,
        )

    def record_checks(self, case_id: str, *, checks: list[Finding]) -> CaseRecord:
        case = self.store.load_case(case_id)
        if case.status != CaseStatus.PROBING:
            raise ValueError("case must be probing before checks are recorded")
        declared_names = {tool.name for tool in case.declared_tools}
        probed_names = {
            probe.tool
            for probe in case.probes
            if probe.completed and probe.accepted
        }
        if not case.probes or not declared_names <= probed_names:
            raise ValueError("every declared tool must be probed before audit completion")
        require_complete_check_matrix(case.declared_tools, checks)
        updated = case.model_copy(
            update={
                "checks": checks,
                "status": CaseStatus.AWAITING_DECISION,
                "audit_completed_at": datetime.now(timezone.utc),
            }
        )
        self.store.save_case(updated)
        return updated

    def seal_case(
        self,
        case_id: str,
        *,
        choice: DecisionChoice,
        approved_tools: list[str],
        approval_required_tools: list[str],
        decision_source: str,
        decided_by: str = "unattested_client_actor",
        human_approval_attested: bool = False,
    ) -> CaseRecord:
        case = self.store.load_case(case_id)
        if case.status != CaseStatus.AWAITING_DECISION:
            raise ValueError("case must be awaiting a decision before it can be sealed")
        if case.audit_completed_at is None or not case.probes:
            raise ValueError("case must have a completed audit before it can be sealed")

        declared_names = {tool.name for tool in case.declared_tools}
        approved = set(approved_tools)
        approval_required = set(approval_required_tools)
        if choice == DecisionChoice.APPROVE_ALL:
            approved = declared_names
        if choice == DecisionChoice.BLOCK:
            approved = set()
            approval_required = set()
        if not approved <= declared_names:
            raise ValueError("approved tools must exist in the inventoried catalog")
        approval_required.update(minimum_approval_tools(case, approved))
        if not approval_required <= approved:
            raise ValueError("approval-gated tools must also be enabled")

        decision = Decision(
            choice=choice,
            approved_tools=sorted(approved),
            approval_required_tools=sorted(approval_required),
            decision_source=decision_source,
            decided_by=decided_by,
            human_approval_attested=human_approval_attested,
        )
        status = (
            CaseStatus.SEALED_BLOCKED
            if choice == DecisionChoice.BLOCK
            else CaseStatus.SEALED_ALLOWED
        )
        updated = case.model_copy(
            update={
                "status": status,
                "decision": decision,
                "enforcement_active": status == CaseStatus.SEALED_ALLOWED,
            }
        )
        self.store.save_case(updated)
        return updated
