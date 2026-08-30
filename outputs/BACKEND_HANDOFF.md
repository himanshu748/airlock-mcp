# Airlock backend handoff

Date: 27 Aug 2026
Version: 0.1.0

Airlock's backend implementation is complete in the workspace. No website, dashboard or custom interface was added.

> Airlock reports what it observed. Absence of a finding is not proof of safety.

## Implemented

- Six-tool control MCP: `open_case`, `list_declared_tools`, `probe_tool`, `read_evidence`, `seal_case` and `emit_policy`
- Per-case MCP recording and enforcing proxy with literal tool allowlists
- MCP 2026-07-28 and legacy request routing validation
- Honest and dishonest owned six-tool fixture servers
- Schema-driven bounded probe generation
- Annotation divergence, undeclared egress, canary movement, filesystem scope escape, injected instruction and schema drift checks
- Aggregate detector matrix with one explicit state per tool and check
- Evidence modes that preserve the distinction between observed, not tested and sensor failed
- Human-decision record plus policy and connector artifact emission
- Downloadable report, policy and connector JSON routes
- Signed case state, derived artifact and private canary-vault persistence
- Exact-URL target credential scope, DNS binding and IP-pinned remote transport
- Request, response, catalog, schema, stream and runtime transcript limits
- Killable, deadline-bound probe planning with lazy candidate materialization and a Linux worker memory ceiling
- Opaque control-plane tool IDs with literal server names quarantined in authenticated artifacts
- SSE filtering across BOM, CR, LF, CRLF and mixed chunk boundaries, with immediate shutdown on server-initiated requests or catalog changes
- Git-backed `airlock-audit` skill and TrueForge agent spec

## Validation

```text
218 backend tests passed
Python bytecode compilation passed
Locked uv environment passed
Dependency consistency check passed
airlock-audit skill validation passed
```

Commands:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q airlock
uv lock --check
uv run --locked --extra dev python -m pytest -q
python3 /Users/himanshujha/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/airlock-audit
```

## External checks still required

- ~~Confirm in a deployed TrueForge run that a literal read-only tool name in `require_approval_for_tools` produces the expected pause.~~ Partly done: a running TrueForge 0.1.4 instance registered the control server and read all six tools with the annotations that drive gating, recorded in `evidence/trueforge-integration.json`. The card rendering itself still needs a model-driven turn.
- Confirm the TrueForge client approval card is shown for `probe_tool`, `seal_case` and `emit_policy`. MCP does not provide the backend with a signed approver identity, so stored decisions are marked unattested.
- Verify Daytona egress visibility if a future `monitored_remote` sensor adapter will depend on it. The current design does not depend on that capability.
- Run the owned fixture targets through the externally reachable proxy URL before recording the demo.

## Deliberate boundaries

- No OAuth-protected target support
- No bundled `monitored_remote` sensor adapter
- One backend process for the JSON case store
- No frontend
