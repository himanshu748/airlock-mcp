export type FindingStatus =
  | "finding"
  | "no_finding_observed"
  | "not_tested"
  | "sensor_failed";

export type Verdict = "block" | "critical" | "suspicious" | null;

export type Check = {
  tool: string;
  check: string;
  status: FindingStatus;
  verdict: Verdict;
  evidence_strength: string;
  sensor: string;
  evidence_refs: string[];
  explanation: string;
};

export type DeclaredTool = {
  name: string;
  description: string;
  annotations: Record<string, unknown>;
  input_schema: Record<string, unknown>;
  probes_run: number;
};

export type CaseSummary = {
  case_id: string;
  target_url: string | null;
  status: string;
  created_at?: string;
  audited_at?: string | null;
  evidence_mode?: string;
  tool_count?: number;
  finding_count?: number;
  probe_budget?: number;
  probes_run?: number;
  enforcement_active?: boolean;
  disclaimer?: string;
  unreadable?: boolean;
};

export type CaseDetail = CaseSummary & {
  airlock_version: string;
  protocol_version: string | null;
  catalog_digest: string | null;
  proxy_url: string | null;
  observation_capabilities: Record<string, boolean>;
  declared_scope: { egress_hosts: string[]; filesystem_roots: string[] };
  runtime_events_dropped: number;
  declared_tools: DeclaredTool[];
  checks: Check[];
  observations: {
    event_id: string;
    probe_id: string;
    tool: string;
    kind: string;
    sensor: string;
    observed_at: string;
  }[];
  decision: {
    choice: string;
    approved_tools: string[];
    approval_required_tools: string[];
    decided_by: string;
    decided_at: string;
    human_approval_attested: boolean;
  } | null;
};

export type StampVerdict = "CLEARED" | "HOLD" | "BLOCKED" | "NOT AUDITED";
export type Tone = "finding" | "hold" | "clear" | "none";
