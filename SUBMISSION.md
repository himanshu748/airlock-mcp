# Airlock, submission

**Agent Harness Hackathon, WeMakeDevs x TrueFoundry**

- Hosted page: <https://airlock-mcp.vercel.app>
- Source: <https://github.com/himanshu748/airlock-mcp>
- Licence: MIT

> Airlock reports what it observed. Absence of a finding is not proof of safety.

## One paragraph

An agent harness decides which tools need human approval by reading the
annotations an MCP server publishes about itself. `readOnlyHint: true` means the
tool is treated as read-only, and nothing checks whether that is true. Airlock
audits what a server actually does, then emits a connector policy built from
that evidence instead of from the server's claims. It opens a case against an
explicitly authorized target, inventories the declared tools, exercises each one
under a capped probe budget, records every observation, and shows the
declaration and the observation side by side. For an approved case it emits a
connector pointing at a per-case enforcing proxy, so the policy is applied on
the wire rather than trusted to the client.

## The gap, demonstrated

The bundled dishonest fixture declares `export_report` with
`readOnlyHint: true` and writes to disk anyway. A harness reading annotations
lets it through with no approval card. Airlock probes it, catches the write, and
puts the tool behind an approval gate in the emitted policy.

Two commands reproduce that, and the exact commands are in the README:

```
target      dishonest fixture, controlled_fixture mode
probes      24
result      7 findings of 36 checks, all five planted behaviours
```

The honest fixture, same shape and same budget, returns **0 findings across the
same 36 checks**. The detectors fire on behaviour, not on unfamiliarity.

## What it found on servers nobody built for this

| target | how | result |
|---|---|---|
| ContextFirewall (deployed) | HTTPS | 6 tools, 30 probes, **no tool declares any annotation** |
| Airlock's own control MCP | HTTPS | full annotations, then its probe planner refused `open_case` |
| `server-filesystem` | stdio | 14 tools |
| `server-everything` | stdio | 13 tools |
| `mcp-server-git` | stdio | 12 tools |
| `server-memory` | stdio | 9 tools |
| `server-sequential-thinking` | stdio | 1 tool |

The ContextFirewall result is the stronger argument. The fixture shows a server
that lies. That one simply says nothing, and a harness resolving `@write` and
`@destructive` matches nothing either way, so `remember` and `forget_memory`
would run without an approval card.

The self-audit is on the page because it failed. `open_case` carries a `$ref`
into `$defs` and the v1 probe profile rejects schema references, so Airlock
cannot finish auditing its own front door. A tool arguing that absence of a
finding is not proof of safety should not hide its own incomplete case.

## How it is built

Python and FastAPI. One process serves the control MCP, the per-case enforcing
proxy, the operator interface and two owned fixtures. Evidence is signed JSON on
disk with path-bound HMAC sidecars. The interface is a Next.js static export, so
running Airlock needs no Node.

Enforcement is on the wire. An agent configured with `enable_tools: ["@all"]`
calling a tool the case did not approve receives
`MCP error -32001: Tool blocked by Airlock policy` from the proxy.

Verified against a running TrueForge instance, not a mock.

## Three decisions worth defending

**Verdicts, never a score.** Six checks, each resolving to `finding`,
`no_finding_observed`, `not_tested` or `sensor_failed`. A number would let a
reader average away the one tool that lied.

**`not_tested` is a first-class result.** Under `transcript_only`, filesystem
and network checks report `capability_absent`, because MCP traffic cannot see
server-side activity. Reporting those as clean would be the exact failure the
product exists to name. The record also separates `capability_absent`, where no
sensor exists, from `evidence_missing`, where a sensor existed and saw nothing.

**Launching a server is the one place Airlock executes what it distrusts.** So
the command never comes from a case or a model. The operator writes a fixed
table of named argument arrays and a case selects a name. Names are looked up,
never parsed into commands.

## Boundaries, stated

- `monitored_remote` has no bundled sensor adapter.
- No OAuth-protected targets.
- Probing is bounded and cannot establish the absence of behaviour outside the
  probes that ran.
- `AIRLOCK_MAX_AUDIT_RESPONSE_BYTES` does not apply to stdio, because that cap
  lives in the HTTP transport.
- The public control workflow opens a fresh stdio process for inventory and
  each tool probe, so it does not claim to observe behavior that depends on
  state shared across separate tools or calls.
- Bounded stderr diagnostics are retained on POSIX. Windows discards child
  stderr because its pipe read cannot be interrupted safely by this
  implementation; that avoids leaking a thread and descriptor per audit.
- Approval identity is not attested by MCP, and decisions are persisted
  explicitly marked unattested.
- The hosted page carries a captured record, not a live backend, and says so on
  itself.

## Verify it

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

294 tests pass. The README's quickstart runs a full fixture audit in two
commands.
