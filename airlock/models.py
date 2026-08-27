from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


AIRLOCK_DISCLAIMER = (
    "Airlock reports what it observed. Absence of a finding is not proof of safety."
)
AIRLOCK_VERSION = "0.1.0"
_MCP_TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_by_name=True)


class CaseStatus(str, Enum):
    CREATED = "created"
    INVENTORIED = "inventoried"
    PROBING = "probing"
    AWAITING_DECISION = "awaiting_decision"
    SEALED_ALLOWED = "sealed_allowed"
    SEALED_BLOCKED = "sealed_blocked"
    INCOMPLETE = "incomplete"


class EvidenceMode(str, Enum):
    CONTROLLED_FIXTURE = "controlled_fixture"
    MONITORED_REMOTE = "monitored_remote"
    TRANSCRIPT_ONLY = "transcript_only"


class EventKind(str, Enum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    NETWORK_EGRESS = "network_egress"
    CANARY_SINK = "canary_sink"
    STATE_CHANGE = "state_change"
    SENSOR_FAILURE = "sensor_failure"
    SENSOR_HEARTBEAT = "sensor_heartbeat"
    PROTOCOL_VERSION_DRIFT = "protocol_version_drift"


class CheckName(str, Enum):
    ANNOTATION_DIVERGENCE = "annotation_divergence"
    UNDECLARED_EGRESS = "undeclared_egress"
    CANARY_EXFILTRATION = "canary_exfiltration"
    SCOPE_ESCAPE = "scope_escape"
    INJECTED_INSTRUCTIONS = "injected_instructions"
    SCHEMA_DRIFT = "schema_drift"


class FindingStatus(str, Enum):
    FINDING = "finding"
    NO_FINDING_OBSERVED = "no_finding_observed"
    NOT_TESTED = "not_tested"
    SENSOR_FAILED = "sensor_failed"


class EvidenceStrength(str, Enum):
    DIRECT = "direct"
    EXTERNAL_ORACLE = "external_oracle"
    HEURISTIC = "heuristic"
    NONE = "none"


class Verdict(str, Enum):
    BLOCK = "block"
    CRITICAL = "critical"
    SUSPICIOUS = "suspicious"


class DecisionChoice(str, Enum):
    BLOCK = "block"
    APPROVE_SELECTED = "approve_selected"
    APPROVE_ALL = "approve_all"


class DeclaredScope(StrictModel):
    egress_hosts: list[str] = Field(default_factory=list)
    filesystem_roots: list[str] = Field(default_factory=list)


class ObservationCapabilities(StrictModel):
    mcp_traffic: bool
    tool_results: bool
    server_egress: bool
    server_filesystem: bool

    @classmethod
    def controlled_fixture(cls) -> "ObservationCapabilities":
        return cls(
            mcp_traffic=True,
            tool_results=True,
            server_egress=True,
            server_filesystem=True,
        )


class TargetBinding(StrictModel):
    scheme: str
    hostname: str
    port: int
    resolved_ips: list[str]


class ToolDeclaration(StrictModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def require_safe_name(cls, name: str) -> str:
        if _MCP_TOOL_NAME.fullmatch(name) is None:
            raise ValueError("tool name does not match the permitted MCP format")
        return name


class ProbeRecord(StrictModel):
    probe_id: str
    tool: str
    kind: str
    request: dict[str, Any] = Field(default_factory=dict)
    accepted: bool
    completed: bool = True
    response_digest: Optional[str] = None
    supplied_canary_ids: list[str] = Field(default_factory=list)


class EvidenceEvent(StrictModel):
    event_id: str
    probe_id: str
    tool: str
    kind: EventKind
    sensor: str
    details: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(StrictModel):
    tool: str
    check: CheckName
    status: FindingStatus
    verdict: Optional[Verdict] = None
    evidence_strength: EvidenceStrength
    sensor: str
    evidence_refs: list[str] = Field(default_factory=list)
    explanation: str


class Decision(StrictModel):
    choice: DecisionChoice
    approved_tools: list[str] = Field(default_factory=list)
    approval_required_tools: list[str] = Field(default_factory=list)
    decision_source: str = Field(min_length=1, max_length=256)
    decided_by: str = Field(
        default="unattested_client_actor",
        min_length=1,
        max_length=256,
    )
    human_approval_attested: bool = False
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseRecord(StrictModel):
    case_id: str
    airlock_version: str = AIRLOCK_VERSION
    target_url: str
    target_binding: Optional[TargetBinding] = None
    created_at: datetime
    status: CaseStatus = CaseStatus.CREATED
    evidence_mode: EvidenceMode = EvidenceMode.TRANSCRIPT_ONLY
    declared_scope: DeclaredScope
    observation_capabilities: ObservationCapabilities
    protocol_version: Optional[str] = None
    auth_context_fingerprint: Optional[str] = None
    catalog_digest: Optional[str] = None
    declared_tools: list[ToolDeclaration] = Field(default_factory=list)
    probe_budget: int = 0
    probes_run: int = 0
    probes: list[ProbeRecord] = Field(default_factory=list)
    events: list[EvidenceEvent] = Field(
        default_factory=list,
        validation_alias=AliasChoices("events", "observations"),
        serialization_alias="observations",
    )
    runtime_events_dropped: int = 0
    checks: list[Finding] = Field(
        default_factory=list,
        validation_alias=AliasChoices("checks", "findings"),
        serialization_alias="findings",
    )
    audit_completed_at: Optional[datetime] = Field(
        default=None,
        validation_alias=AliasChoices("audit_completed_at", "audited_at"),
        serialization_alias="audited_at",
    )
    decision: Optional[Decision] = None
    proxy_url: Optional[str] = None
    enforcement_active: bool = False
    disclaimer: str = AIRLOCK_DISCLAIMER

    @classmethod
    def new(
        cls,
        *,
        case_id: str,
        target_url: str,
        declared_scope: DeclaredScope,
        observation_capabilities: ObservationCapabilities,
        evidence_mode: EvidenceMode = EvidenceMode.TRANSCRIPT_ONLY,
        proxy_url: Optional[str] = None,
        target_binding: Optional[TargetBinding] = None,
    ) -> "CaseRecord":
        return cls(
            case_id=case_id,
            target_url=target_url,
            target_binding=target_binding,
            created_at=datetime.now(timezone.utc),
            declared_scope=declared_scope,
            observation_capabilities=observation_capabilities,
            evidence_mode=evidence_mode,
            proxy_url=proxy_url,
        )
