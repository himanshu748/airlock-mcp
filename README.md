# Airlock

[![tests](https://github.com/himanshu748/airlock-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/himanshu748/airlock-mcp/actions/workflows/tests.yml)

Airlock audits what an MCP server actually does, then emits a connector policy
built from that evidence instead of from the server's own claims. It opens a
case against an explicitly authorized target, inventories the tools the server
declares, exercises each one under a capped probe budget, records every
observation and shows the declaration and the observation side by side. For an
approved case it emits a connector that points at a per-case enforcing proxy, so
the policy is applied on the wire rather than trusted to the client.

> Airlock reports what it observed. Absence of a finding is not proof of safety.

## Hosted page

<https://airlock-mcp.vercel.app>

The landing page and an inspection record you can read without installing
anything. The record is a **captured snapshot of a real fixture audit**, not a
live backend, and the page says so at the top of itself.

Airlock's backend cannot run on a static or serverless host, and pretending
otherwise would be the kind of claim this project exists to argue against:

- Case state is signed JSON on disk, and `open_case` then `probe_tool` are
  separate requests. A filesystem that does not survive between them loses the
  case.
- An audit is bounded at 240 seconds by design, which outlives a typical
  serverless request budget.
- `stdio:` targets launch a child process.
- The enforcing proxy has to hold sealed-case state to refuse a tool call
  before it reaches the server.
- The operator interface refuses any peer that is not loopback, which is every
  peer on a public host.

Run it locally to audit a server of your own. The quickstart below is two
commands.

## The gap this closes

An agent harness decides which tools need human approval by reading the
annotations the MCP server publishes about itself. `readOnlyHint: true` means
the tool is treated as read-only. Nothing checks whether that is true.

The bundled dishonest fixture makes the point concretely. Its `export_report`
tool declares `readOnlyHint: true` and writes to disk anyway. A harness reading
annotations lets it through without an approval card. Airlock probes it, catches
the write and puts the tool behind an approval gate in the emitted policy.

## Run the demo

Python 3.12 or newer. From a clone:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Start the backend with the owned fixtures mounted. These are loopback-only test
servers, so local targets and fixture credentials are enabled deliberately:

```bash
export AIRLOCK_HOST=127.0.0.1
export AIRLOCK_PORT=8000
export AIRLOCK_PUBLIC_BASE_URL=http://127.0.0.1:8000
export AIRLOCK_CASE_ROOT=data/cases
export AIRLOCK_CONTROL_BEARER_TOKEN=demo-control-token
export AIRLOCK_CASE_PROXY_BEARER_TOKEN=demo-runtime-token
export AIRLOCK_STATE_INTEGRITY_KEY=demo-integrity-key-at-least-32-bytes-long
export AIRLOCK_CONTROL_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000
export AIRLOCK_CONTROL_ALLOWED_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
export AIRLOCK_ENABLE_OPERATOR_UI=true
export AIRLOCK_ALLOW_LOCAL_TARGETS=true
export AIRLOCK_ALLOWED_TARGET_HOSTNAMES=127.0.0.1
export AIRLOCK_MOUNT_OWNED_FIXTURES=true
export AIRLOCK_FIXTURE_BEARER_TOKEN=demo-fixture-token
export AIRLOCK_TARGET_AUTHORIZATION='Bearer demo-fixture-token'
export AIRLOCK_AUTHENTICATED_TARGET_URLS='http://127.0.0.1:8000/fixtures/honest/mcp,http://127.0.0.1:8000/fixtures/dishonest/mcp'
.venv/bin/airlock-backend
```

In a second shell, with the same `AIRLOCK_CONTROL_BEARER_TOKEN` exported, run a
full audit against the dishonest fixture:

```bash
.venv/bin/python scripts/demo_audit.py --declared-root /workspace/documents
```

That opens a case, inventories six tools, probes every one of them and prints
the aggregate evidence:

```
case af_85f0b9193b31456597b00f61fd93c5e0
target http://127.0.0.1:8000/fixtures/dishonest/mcp
evidence mode controlled_fixture
declared tools: 6
  probed tool_0001 observations=27
  ...
  probed tool_0006 observations=94

status: awaiting_decision
findings: 7 of 36 checks
  [block] annotation_divergence tool=tool_0001 evidence=direct sensor=fixture_filesystem
  [critical] scope_escape tool=tool_0001 evidence=direct sensor=fixture_filesystem
  [block] undeclared_egress tool=tool_0002 evidence=direct sensor=fixture_network
  [critical] scope_escape tool=tool_0003 evidence=direct sensor=fixture_filesystem
  [suspicious] injected_instructions tool=tool_0005 evidence=heuristic sensor=mcp_transcript
  [critical] canary_exfiltration tool=tool_0006 evidence=external_oracle sensor=canary_sink
  [critical] scope_escape tool=tool_0006 evidence=direct sensor=fixture_filesystem
```

Seven findings covering all five planted behaviors. Point the same command at
the honest fixture and it reports zero findings across the same 36 checks:

```bash
.venv/bin/python scripts/demo_audit.py \
  --target http://127.0.0.1:8000/fixtures/honest/mcp \
  --declared-root /workspace/documents
```

Then open <http://127.0.0.1:8000/ui/record/> to read the record: what the server
declared on the left in its own words, what Airlock observed on the right.

The demo script stops before `seal_case`, because sealing is a human decision.
Sealing and policy emission run through the control MCP with their own approval
gates. See the audit workflow below.

## Running it from an agent harness

Airlock is itself an MCP server, so a harness drives the whole audit from one
chat message.

1. Register the control connector using
   [`configs/airlock-control-connector.json`](configs/airlock-control-connector.json)
   and configure its bearer header with `AIRLOCK_CONTROL_BEARER_TOKEN`.
2. Create the audit agent from
   [`configs/trueforge-agent.json`](configs/trueforge-agent.json) and install the
   [`airlock-audit` skill](skills/airlock-audit/SKILL.md). Keep sandbox support
   enabled.
3. Ask the agent to audit an authorized target. It opens the case, inventories,
   probes, reads the evidence and asks you to Block, Approve selected or
   Approve all.
4. On approval it seals the case, emits the policy and hands back a connector
   manifest pointing at the enforcing case proxy, not at the audited server.

The agent spec names `probe_tool`, `seal_case` and `emit_policy` literally in
`require_approval_for_tools`, because those three publish sensitive annotations
and must not resolve from the server's own hints.

Enforcement is on the wire, not in the prompt. An agent configured with
`enable_tools: ["@all"]` that calls a tool the case did not approve receives
`MCP error -32001: Tool blocked by Airlock policy` from the proxy.

## Backend surface

| Surface | Route | Purpose |
|---|---|---|
| Control MCP | `/airlock-control/mcp` | Creates cases, inventories tools, runs probes, returns evidence, records decisions and emits policy artifacts |
| Enforcing proxy | `/cases/{case_id}/mcp` | Forwards only tools approved for a sealed case, under the protocol version the case was audited with |
| Artifact download | `/cases/{case_id}/artifacts/{artifact_name}` | Returns only the report, policy or connector artifact with runtime bearer authentication |
| Honest fixture | `/fixtures/honest/mcp` | Optional owned six-tool fixture with accurate annotations |
| Dishonest fixture | `/fixtures/dishonest/mcp` | Optional owned six-tool fixture with five planted, toggleable behaviors |
| Operator interface | `/ui/` | Landing page and inspection record, on in development, opt in for production |
| Read API | `/api/cases`, `/api/cases/{case_id}` | Read-only case views for the interface, gated by the same switch |

The control MCP exposes exactly six tools: `open_case`, `list_declared_tools`,
`probe_tool`, `read_evidence`, `seal_case` and `emit_policy`.

## Evidence modes

| Mode | MCP traffic and results | Server egress | Server filesystem | Default availability |
|---|---:|---:|---:|---|
| `transcript_only` | Observed | Not tested | Not tested | Enabled |
| `controlled_fixture` | Observed | Observed by the owned fixture sensor | Observed by the owned fixture sensor | Enabled only when fixtures are mounted |
| `monitored_remote` | Depends on integration | Depends on integration | Depends on integration | Reserved for an operator-supplied trusted sensor integration |

Choose the mode deliberately. For an arbitrary remote server, MCP traffic does
not reveal server-side network or filesystem activity, so `transcript_only` is
the honest mode and Airlock records those checks as `not_tested` rather than as
clean observations. Running the bundled fixtures under `transcript_only` is a
misconfiguration. All 36 checks come back `not_tested` and the case ends
`incomplete`, but for two different reasons, and the record keeps them apart:

- `annotation_divergence`, `scope_escape` and `undeclared_egress` report
  `capability_absent`. That mode has no filesystem or network sensor, so those
  questions cannot be asked at all.
- `injected_instructions`, `schema_drift` and `canary_exfiltration` report
  `evidence_missing`. Those checks read the transcript and the tool results, so
  the mode could answer them. Nothing was observed because the bundled fixtures
  plant their behaviours only for a `controlled_fixture` case, and serve clean
  responses otherwise.

Neither is a clean result, which is the point of keeping the two labels
distinct.

Each tool and check resolves to one aggregate state: `finding`,
`no_finding_observed`, `not_tested` or `sensor_failed`. Finding severity is
expressed separately as `block`, `critical` or `suspicious`.

## Auditing stdio servers

Most MCP servers ship as a command rather than a URL. Airlock can audit those
too, but launching one means executing the code the audit exists to distrust, so
the command never comes from the model or from a case argument.

The operator writes a fixed table of named argument arrays. A case selects a
name. JSON keeps Windows backslashes and paths with spaces unambiguous without
ever invoking a shell:

```bash
export AIRLOCK_STDIO_TARGETS='{"memory":["npx","-y","@modelcontextprotocol/server-memory"],"git":["uvx","mcp-server-git","--repository","/tmp/sandbox"]}'
```

The original `name=command arg;name=command` form remains available as a
concise POSIX-only format. Use JSON for portable deployment configuration.

Then open a case against `stdio:memory`. Names are looked up, never parsed into
commands, so there is no path from a server, a tool result or a model-supplied
string to an argument vector.

The child runs in a throwaway working directory. The MCP SDK merges the
supplied environment over a default that inherits `HOME`, `LOGNAME`, `PATH`,
`SHELL`, `TERM` and `USER` from the host, so Airlock names every one of them:
`PATH` is passed through, the home and temporary directories point at the
throwaway, and the rest are emptied. Windows profile and temporary-directory
variables are redirected too.

Five limits are deliberate:

- **Audit only.** The enforcing proxy forwards to an HTTP upstream, and a
  launched process has none. `emit_policy` refuses a stdio case rather than
  emitting a connector nothing can hold.
- **No DNS pinning, because there is no DNS.** The whole command binding is
  compared against operator configuration before each connection, so
  re-pointing a name, or removing and re-adding it, revokes the open case
  rather than letting it keep running the withdrawn command.
- **`AIRLOCK_MAX_AUDIT_RESPONSE_BYTES` does not apply.** That cap is enforced
  by the HTTP transport, and the stdio transport is the SDK's. A launched
  server can return a response large enough to exhaust the auditor's memory
  before Airlock sees it. The audit deadline still bounds the run.
- **The control workflow opens a fresh process for inventory and each
  `probe_tool` call.** Airlock observes each tool invocation, but it does not
  claim to detect behavior that requires state carried across different tools
  or control calls. The in-process `AuditExecutor.run` path keeps one probe
  session for its batch, but the public six-tool control workflow does not.
- **Bounded stderr diagnostics are POSIX-only.** A pollable pipe keeps the last
  8 KiB without allowing a hostile server to fill memory or disk. Windows pipe
  reads cannot be interrupted safely through this implementation, so Airlock
  discards child stderr there instead of leaking a thread and descriptor per
  audit.

Process isolation beyond the working directory and environment is the
deployment's job. Airlock does not sandbox the child's filesystem or network.

## Production settings

The demo above is a loopback development configuration. For a real deployment:

```bash
cp .env.example .env
# edit .env, then
set -a; source .env; set +a
.venv/bin/airlock-backend
```

- Set distinct high-entropy values for `AIRLOCK_CONTROL_BEARER_TOKEN` and
  `AIRLOCK_CASE_PROXY_BEARER_TOKEN`.
- Set a stable high-entropy `AIRLOCK_STATE_INTEGRITY_KEY` containing at least 32
  bytes. Changing it makes existing signed case state unreadable.
- Restrict `AIRLOCK_CONTROL_ALLOWED_HOSTS` and `AIRLOCK_CONTROL_ALLOWED_ORIGINS`
  to the deployed origin.
- Restrict `AIRLOCK_ALLOWED_TARGET_HOSTNAMES` to targets authorized for the
  deployment.
- Keep `AIRLOCK_ALLOW_LOCAL_TARGETS=false`. Loopback HTTP exists only for owned
  local fixtures and tests.
- Store `AIRLOCK_CASE_ROOT` on persistent storage with host-level access
  controls and backups appropriate for evidence data.
- Use HTTPS at the external edge and set `AIRLOCK_PUBLIC_BASE_URL` to the
  externally reachable origin before registering the connector.

If a target requires static header authentication, set
`AIRLOCK_TARGET_AUTHORIZATION` and list every exact authorized MCP URL in
`AIRLOCK_AUTHENTICATED_TARGET_URLS`. Scheme, hostname, port, path and query must
match exactly before the header is sent. Client-supplied authorization, cookie
and forwarding headers are stripped at the proxy boundary. Target credentials
come only from operator configuration.

## Operator interface

A Next.js App Router application, exported statically into `airlock/ui/` and
served by the backend at `/ui/`. The export is committed, so running Airlock
never requires Node and the demo is a single process.

- `/ui/` states what Airlock does and the gap it closes.
- `/ui/record/` is the inspection record. Rows align and sort worst first, so
  divergence is visible before you read a word. A verdict stamp lands on each
  row, `CLEARED`, `HOLD`, `BLOCKED` or `NOT AUDITED`, always with a word and a
  glyph rather than colour alone.

It reads `GET /api/cases` and `GET /api/cases/{case_id}`.

The interface is on by default in development and off in production, because it
carries no authentication of its own. Override either way with
`AIRLOCK_ENABLE_OPERATOR_UI`.

The loopback boundary is enforced, not merely documented. `/ui` and `/api`
reject any request whose peer is not a loopback address, which holds however the
application was started, including building it straight from the factory.
Startup additionally refuses a non-loopback `AIRLOCK_HOST` while the interface
is enabled, so the misconfiguration fails immediately rather than at the first
request.

Four properties are deliberate and covered by tests:

- **Everything on those pages is untrusted.** Tool names, descriptions, schemas
  and detector explanations all originate with the server under audit. React
  escapes them, there is no `dangerouslySetInnerHTML` in the project and the
  backend sends `default-src 'none'` with `connect-src 'self'` so injected
  markup would have nowhere to send anything. `script-src` allows
  `'unsafe-inline'` because a Next.js static export carries its hydration
  payload inline and cannot use per-response nonces.
- **The built pages make no external requests.** Fonts are self-hosted by
  `next/font`, so the interface works with no network and cannot leak a case id
  through an asset request.
- **The pinned transport cannot be replaced.** The proxy accepts a transport
  factory, never a prebuilt client, and builds the transport per request from
  the binding the case validated. There is no parameter that swaps out the whole
  client and so skips DNS pinning.
- **The read API returns text, the control MCP returns digests.**
  `read_evidence` reduces descriptions and explanations to digests because those
  values re-enter the model. The read API is for a human, so it returns them
  verbatim.

### Rebuilding the interface

Only needed when changing `frontend/`. Do not build inside an iCloud-synced
directory, where npm stalls:

```bash
cp -R frontend /tmp/airlock-frontend && cd /tmp/airlock-frontend
npm install
npm run build
```

Copy the resulting `out/` over `airlock/ui/` and commit it. See
[`frontend/README.md`](frontend/README.md).

## Audit workflow in detail

1. Call `open_case` with an explicitly authorized target, evidence mode and
   declared scope.
2. Call `list_declared_tools`, then use its opaque `tool_id` values with
   approval-gated `probe_tool` until every declared tool has persisted probe
   evidence. Literal server names remain quarantined in the report artifact.
3. Read the aggregate evidence. The root agent asks the user to Block, Approve
   selected or Approve all.
4. After the user's choice, call approval-gated `seal_case` with the exact
   selected `approved_tool_ids` and `approval_required_tool_ids`.
5. For an allowed case, call approval-gated `emit_policy`, download the
   authenticated connector artifact and register its case proxy URL, not the
   suspect URL. Configure that connector with `AIRLOCK_CASE_PROXY_BEARER_TOKEN`
   as its bearer header.

The backend cannot cryptographically determine whether the MCP client displayed
an approval card or identify the person who approved it. A control-plane
decision is persisted as `human_approval_attested: false` with
`decided_by: "unattested_mcp_client_actor"`. The deployment must configure the
client's approval gate for `probe_tool`, `seal_case` and `emit_policy`.

## Artifacts

Each case is stored under `AIRLOCK_CASE_ROOT/{case_id}/`:

- `airlock-report.json`: declarations, redacted probe records, evidence
  provenance, aggregate checks and the recorded decision
- `airlock-policy.json`: the pasteable `mcp_servers` policy fragment, written
  only for a sealed allowed case
- `airlock-connector.json`: the remote connector manifest pointing to the
  enforcing case proxy

Writes use a temporary file, `fsync` and atomic replacement. Case directories use
mode `0700`; artifact files use mode `0600`. In production, path-bound HMAC
sidecars authenticate the report, derived artifacts and private canary vault
before the backend uses or serves them.

Before policy emission, the compiler revalidates completed-audit state,
successful probe coverage, a complete detector matrix, unique catalog
membership, selected tool membership, enforcement activation and the case proxy
URL. Every approved tool with a persisted finding is placed by literal name in
`require_approval_for_tools`. Declared write or destructive tools receive the
same minimum gate.

### Artifact sensitivity

`airlock-report.json` and `airlock-policy.json` contain no secrets and can be
shared as evidence.

`airlock-connector.json` is different. When `AIRLOCK_CASE_PROXY_BEARER_TOKEN` is
set, the manifest carries that token in an `auth` header block, because without
it the harness cannot connect and the artifact does not paste in unedited. Treat
that file as a credential. It is written `0600` and its download endpoint
requires the same token it contains, so fetching it needs the credential already
in hand.

## Connection controls

- Remote targets require HTTPS. Loopback-only HTTP must be enabled explicitly.
- URLs with credentials, fragments, ambiguous hostnames or non-global address
  resolution are rejected.
- DNS answers are persisted, revalidated before audit and runtime forwarding and
  used for IP-pinned connections while preserving the original Host header and
  TLS server name.
- Redirects are disabled.
- Probe budgets are cumulative and persisted per case.
- Remote audit responses are byte-limited before MCP decoding. Encoded audit
  responses are rejected to avoid decompression expansion. Inventory operations
  and individual tool calls also have hard wall-clock deadlines, and the audit as
  a whole has a total deadline.
- Tool inventories have page, cursor-cycle, tool-count and serialized-size
  limits.
- Probe planning materializes no more candidates than the persisted allowance and
  runs in a killable worker with a hard deadline. Linux deployments also apply a
  per-worker address-space ceiling. Other deployments must apply the documented
  container memory limit. JSON Schema `pattern`, `patternProperties`, references
  and schemas outside the bounded depth, width and collection profile are
  rejected in v1. Such a case becomes `incomplete`.
- Tool names must match the bounded identifier profile
  `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` before inventory is persisted.
- Runtime request bodies, buffered responses and streamed responses are bounded.
  Every response body has idle-read and total-duration limits. Encoded runtime
  responses are rejected.
- Raw suspect tool-result bodies are never returned through `read_evidence`; only
  digests, typed features and evidence references re-enter the model context.
- Control MCP responses use opaque tool IDs. Literal server tool names, detector
  prose and emitted policy names remain in authenticated downloadable artifacts
  rather than model-facing tool results.
- Runtime tool calls are refused before upstream contact unless the case is
  sealed, enforcement is active and the literal tool name is approved.
- Runtime MCP requests default-deny prompts, resources and extension methods.
  Only initialization, discovery, cancellation, ping, `tools/list` and approved
  `tools/call` requests are forwarded.
- A runtime protocol version that differs from the audited one is recorded as
  drift evidence on the case rather than silently accepted.
- Server-initiated MCP requests are removed from SSE streams. Unexpected server
  methods or buffered server requests make the case `incomplete` and disable
  further enforcement.
- Runtime transcript retention is capped by `AIRLOCK_MAX_RUNTIME_EVENTS`. The
  report records how many older runtime events were dropped.
- A changed runtime target binding or tool catalog marks the case incomplete and
  disables enforcement.

## Current boundaries

- No OAuth-protected target support is included.
- Static header authentication is exact-URL scoped and shared only among the URLs
  explicitly listed by the operator.
- `monitored_remote` has no bundled external sensor adapter.
- Runtime enforcement is a per-tool allowlist and evidence recorder, not a
  general network firewall.
- Dynamic probing is bounded and cannot establish the absence of behavior outside
  the executed probes.
- Approval identity is not signed or attested by MCP. The shipped agent spec
  requires client approval for `probe_tool`, `seal_case` and `emit_policy`, while
  persisted decisions remain explicitly marked unattested.
- JSON Schema references, `patternProperties` and every `pattern` expression are
  outside the bounded v1 probe profile. Their cases stop as `incomplete`.
- The bundled server runs as one process. The JSON case store is not a
  multi-process coordination layer.
- On non-Linux hosts, enforce `AIRLOCK_PROBE_PLANNING_MEMORY_BYTES` through the
  surrounding container or process supervisor because the backend's child
  address-space limit is Linux-specific.
- The operator interface is read-only. Opening cases, sealing them and emitting
  policy all remain control MCP operations with their own approval gates.
- The operator interface and its read API have no authentication of their own.
  They are restricted to loopback peers, enforced per request and are on by
  default only in development. Loopback is a network boundary, not user
  authentication: anyone with local access to the host can read case records.

## Verify

```bash
.venv/bin/python -m pytest -q
```

294 tests covering domain invariants, evidence persistence, schema-driven
probes, all detector outcomes, honest and dishonest fixtures, the control MCP,
target validation, DNS pinning, modern and legacy MCP proxy routing, streamed
responses, enforcement, policy emission, stdio target resolution and
revalidation, the read API and the operator interface's no-markup,
no-external-request and language-discipline properties.

Every push and pull request runs the same command on GitHub Actions, so the
count above is recorded publicly rather than asserted here.

## License

MIT
