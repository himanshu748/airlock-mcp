# Airlock backend

Airlock compares an MCP server's declarations with bounded observations, records the evidence and emits a connector policy enforced by a per-case proxy. This repository contains the backend only. It does not include a website, dashboard or custom interface.

> Airlock reports what it observed. Absence of a finding is not proof of safety.

## Backend surface

| Surface | Route | Purpose |
|---|---|---|
| Control MCP | `/airlock-control/mcp` | Creates cases, inventories tools, runs probes, returns evidence, records decisions and emits policy artifacts |
| Enforcing proxy | `/cases/{case_id}/mcp` | Forwards only tools approved for a sealed case, under the protocol version the case was audited with |
| Artifact download | `/cases/{case_id}/artifacts/{artifact_name}` | Returns only the report, policy or connector artifact with runtime bearer authentication |
| Honest fixture | `/fixtures/honest/mcp` | Optional owned six-tool fixture with accurate annotations |
| Dishonest fixture | `/fixtures/dishonest/mcp` | Optional owned six-tool fixture with five planted, toggleable behaviors |

The control MCP exposes exactly six tools:

- `open_case`
- `list_declared_tools`
- `probe_tool`
- `read_evidence`
- `seal_case`
- `emit_policy`

`probe_tool`, `seal_case` and `emit_policy` publish destructive annotations so the MCP client can require approval for them. The shipped agent spec also names all three literally in its approval policy.

## Evidence modes

| Mode | MCP traffic and results | Server egress | Server filesystem | Default availability |
|---|---:|---:|---:|---|
| `transcript_only` | Observed | Not tested | Not tested | Enabled |
| `controlled_fixture` | Observed | Observed by the owned fixture sensor | Observed by the owned fixture sensor | Enabled only when fixtures are mounted |
| `monitored_remote` | Depends on integration | Depends on integration | Depends on integration | Reserved for an operator-supplied trusted sensor integration |

For arbitrary remote servers, MCP traffic does not reveal server-side network or filesystem activity. Airlock therefore records those checks as `not_tested`, never as a clean observation.

Each tool and check resolves to one aggregate state: `finding`, `no_finding_observed`, `not_tested` or `sensor_failed`. Finding severity is expressed separately as `block`, `critical` or `suspicious`.

## Install and run

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp .env.example .env
set -a
source .env
set +a
.venv/bin/airlock-backend
```

The development defaults bind to `127.0.0.1:8000`. Use HTTPS at the external edge and set `AIRLOCK_PUBLIC_BASE_URL` to the externally reachable origin before registering the connector.

### Required production settings

- Set distinct high-entropy values for `AIRLOCK_CONTROL_BEARER_TOKEN` and `AIRLOCK_CASE_PROXY_BEARER_TOKEN`.
- Set a stable high-entropy `AIRLOCK_STATE_INTEGRITY_KEY` containing at least 32 bytes. Changing it makes existing signed case state unreadable.
- Restrict `AIRLOCK_CONTROL_ALLOWED_HOSTS` and `AIRLOCK_CONTROL_ALLOWED_ORIGINS` to the deployed origin.
- Restrict `AIRLOCK_ALLOWED_TARGET_HOSTNAMES` to targets authorized for the deployment.
- Keep `AIRLOCK_ALLOW_LOCAL_TARGETS=false`. Loopback HTTP exists only for owned local fixtures and tests.
- Store `AIRLOCK_CASE_ROOT` on persistent storage with host-level access controls and backups appropriate for evidence data.

If a target requires static header authentication, set `AIRLOCK_TARGET_AUTHORIZATION` and list every exact authorized MCP URL in `AIRLOCK_AUTHENTICATED_TARGET_URLS`. Scheme, hostname, port, path and query must match exactly before the header is sent. Client-supplied authorization, cookie and forwarding headers are stripped at the proxy boundary. Target credentials come only from operator configuration.

## Owned fixture run

The fixture endpoints are disabled by default. For a local, loopback-only detector exercise:

```bash
export AIRLOCK_ALLOW_LOCAL_TARGETS=true
export AIRLOCK_ALLOWED_TARGET_HOSTNAMES=127.0.0.1
export AIRLOCK_MOUNT_OWNED_FIXTURES=true
export AIRLOCK_FIXTURE_BEARER_TOKEN='replace-with-a-random-fixture-token'
export AIRLOCK_TARGET_AUTHORIZATION='Bearer replace-with-a-random-fixture-token'
export AIRLOCK_AUTHENTICATED_TARGET_URLS='http://127.0.0.1:8000/fixtures/honest/mcp,http://127.0.0.1:8000/fixtures/dishonest/mcp'
.venv/bin/airlock-backend
```

Use these submitted targets:

- `http://127.0.0.1:8000/fixtures/honest/mcp`
- `http://127.0.0.1:8000/fixtures/dishonest/mcp`

The dishonest fixture enables all five planted behaviors when mounted through the environment entry point: a read-only claim that writes, undeclared egress, canary movement, filesystem scope escape and an instruction embedded in a tool result. The fixture records sensor events directly into the matching `controlled_fixture` case. It does not contact an external sink.

## Audit workflow

1. Register the control connector using [`configs/airlock-control-connector.json`](configs/airlock-control-connector.json) and configure its bearer header.
2. Create the audit agent from [`configs/trueforge-agent.json`](configs/trueforge-agent.json), install the [`airlock-audit` skill](skills/airlock-audit/SKILL.md) and keep sandbox support enabled.
3. Call `open_case` with an explicitly authorized target, evidence mode and declared scope.
4. Call `list_declared_tools`, then use its opaque `tool_id` values with approval-gated `probe_tool` until every declared tool has persisted probe evidence. Literal server names remain quarantined in the report artifact.
5. Read the aggregate evidence. The root agent asks the user to Block, Approve selected or Approve all.
6. After the user's choice, call approval-gated `seal_case` with the exact selected `approved_tool_ids` and `approval_required_tool_ids`.
7. For an allowed case, call approval-gated `emit_policy`, download the authenticated connector artifact and register its case proxy URL, not the suspect URL. Configure that connector with `AIRLOCK_CASE_PROXY_BEARER_TOKEN` as its bearer header.

The backend cannot cryptographically determine whether the MCP client displayed an approval card or identify the person who approved it. A control-plane decision is persisted as `human_approval_attested: false` with `decided_by: "unattested_mcp_client_actor"`. The deployment must configure the client's approval gate for `probe_tool`, `seal_case` and `emit_policy`.

## Artifacts

Each case is stored under `AIRLOCK_CASE_ROOT/{case_id}/`:

- `airlock-report.json`: declarations, redacted probe records, evidence provenance, aggregate checks and the recorded decision
- `airlock-policy.json`: the pasteable `mcp_servers` policy fragment, written only for a sealed allowed case
- `airlock-connector.json`: the remote connector manifest pointing to the enforcing case proxy

Writes use a temporary file, `fsync` and atomic replacement. Case directories use mode `0700`; artifact files use mode `0600`. In production, path-bound HMAC sidecars authenticate the report, derived artifacts and private canary vault before the backend uses or serves them.

Before policy emission, the compiler revalidates completed-audit state, successful probe coverage, a complete detector matrix, unique catalog membership, selected tool membership, enforcement activation and the case proxy URL. Every approved tool with a persisted finding is placed by literal name in `require_approval_for_tools`. Declared write or destructive tools receive the same minimum gate.

## Connection controls

- Remote targets require HTTPS. Loopback-only HTTP must be enabled explicitly.
- URLs with credentials, fragments, ambiguous hostnames or non-global address resolution are rejected.
- DNS answers are persisted, revalidated before audit and runtime forwarding and used for IP-pinned connections while preserving the original Host header and TLS server name.
- Redirects are disabled.
- Probe budgets are cumulative and persisted per case.
- Remote audit responses are byte-limited before MCP decoding. Encoded audit responses are rejected to avoid decompression expansion. Inventory operations and individual tool calls also have hard wall-clock deadlines.
- Tool inventories have page, cursor-cycle, tool-count and serialized-size limits.
- Probe planning materializes no more candidates than the persisted allowance and runs in a killable worker with a hard deadline. Linux deployments also apply a per-worker address-space ceiling. Other deployments must apply the documented container memory limit. JSON Schema `pattern`, `patternProperties`, references and schemas outside the bounded depth, width and collection profile are rejected in v1. Such a case becomes `incomplete`.
- Tool names must match the bounded identifier profile `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` before inventory is persisted.
- Runtime request bodies, buffered responses and streamed responses are bounded. Every response body has idle-read and total-duration limits. Encoded runtime responses are rejected.
- Raw suspect tool-result bodies are never returned through `read_evidence`; only digests, typed features and evidence references re-enter the model context.
- Control MCP responses use opaque tool IDs. Literal server tool names, detector prose and emitted policy names remain in authenticated downloadable artifacts rather than model-facing tool results.
- Runtime tool calls are refused before upstream contact unless the case is sealed, enforcement is active and the literal tool name is approved.
- Runtime MCP requests default-deny prompts, resources and extension methods. Only initialization, cancellation, ping, `tools/list` and approved `tools/call` requests are forwarded.
- Server-initiated MCP requests are removed from SSE streams. Unexpected server methods or buffered server requests make the case `incomplete` and disable further enforcement.
- Runtime transcript retention is capped by `AIRLOCK_MAX_RUNTIME_EVENTS`. The report records how many older runtime events were dropped.
- A changed runtime target binding or tool catalog marks the case incomplete and disables enforcement.

## Current boundaries

- No OAuth-protected target support is included.
- Static header authentication is exact-URL scoped and shared only among the URLs explicitly listed by the operator.
- `monitored_remote` has no bundled external sensor adapter.
- Runtime enforcement is a per-tool allowlist and evidence recorder, not a general network firewall.
- Dynamic probing is bounded and cannot establish the absence of behavior outside the executed probes.
- Approval identity is not signed or attested by MCP. The shipped agent spec requires client approval for `probe_tool`, `seal_case` and `emit_policy`, while persisted decisions remain explicitly marked unattested.
- JSON Schema references, `patternProperties` and every `pattern` expression are outside the bounded v1 probe profile. Their cases stop as `incomplete`.
- The bundled server runs as one process. The JSON case store is not a multi-process coordination layer.
- On non-Linux hosts, enforce `AIRLOCK_PROBE_PLANNING_MEMORY_BYTES` through the surrounding container or process supervisor because the backend's child address-space limit is Linux-specific.
- No frontend is included.

## Verify

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q airlock
python3 /Users/himanshujha/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/airlock-audit
```

The test suite covers domain invariants, evidence persistence, schema-driven probes, all detector outcomes, honest and dishonest fixtures, the control MCP, target validation, DNS pinning, modern and legacy MCP proxy routing, streamed responses, enforcement and policy emission.
