# Agent Harness Hackathon: form answers and video plan

Form: https://docs.google.com/forms/d/e/1FAIpQLSd2DDM-F0BJUqxu8if-XjCZufWH_mRVOlZTYAqsQXL2cNdjYA/viewform

## Video requirements, verbatim from the form

> The video should be not be more than 3 minutes covering how your project
> reflects the below points: About the project, Tech stack and architecture,
> Demo if possible, Learning and growth (optional)

- **Hard cap: 3 minutes.**
- **YouTube link required.** Unlisted is fine, Private is not: a judge with the
  link must be able to play it without requesting access.

---

**Track:** Best Use of TrueForge (Airlock is also a strong Best Code Quality entry)
**GitHub:** https://github.com/himanshu748/airlock-mcp
**Deployed:** https://airlock-mcp.vercel.app

## What does your project do?

Your agent harness pauses before sensitive tool calls. Which tools count as
sensitive comes from annotations the MCP server publishes about itself. Nothing
in the protocol requires those annotations to be true, and nothing in the client
checks them.

Airlock audits what an MCP server actually does, then emits a connector policy
built from that evidence instead of from the server's claims. It opens a case
against an explicitly authorized target, inventories the declared tools,
exercises each under a capped probe budget, and shows the declaration and the
observation side by side. For an approved case it emits a connector pointing at
a per-case enforcing proxy, so the policy is applied on the wire rather than
trusted to the client.

The users are anyone about to connect a third-party MCP server to an agent that
can act on their behalf.

It reports what it observed. Absence of a finding is not proof of safety, and
the interface says so on every screen.

## How did you use TrueForge in your project?

Airlock is itself an MCP server, so a TrueForge agent drives an entire audit
from one chat message: open the case, inventory, probe each tool, read the
evidence, decide.

- **Real MCP tools.** The control server exposes six, registered with real
  annotations.
- **Human approval before irreversible action.** `probe_tool`, `seal_case` and
  `emit_policy` are named literally in `require_approval_for_tools`, because
  those three exercise a live server, seal a case or publish a policy. They must
  never resolve from a server's own hints, which is the exact failure Airlock
  exists to detect.
- **Sandboxed execution.** The agent spec keeps sandbox support enabled, and
  stdio targets launch in a throwaway working directory with a fully controlled
  environment.
- **Enforcement on the wire, not in the prompt.** An agent configured with
  `enable_tools: ["@all"]` calling a tool the case did not approve receives
  `MCP error -32001: Tool blocked by Airlock policy` from the proxy. That is not
  a refusal a model can be argued out of.

The gating is enforced by tests that build the control server and ask it what it
registered, rather than trusting a hand-copied list.

## How did you use Qodo in your project?

Fourteen pull requests, every substantive change reviewed by Qodo before merge.
The reviews changed the code rather than rubber-stamping it.

- **[#9](https://github.com/himanshu748/airlock-mcp/pull/9)** four real bugs in
  the stdio transport, two of them security. Revalidation compared only the
  target name, so re-pointing a name left an open case executing a command the
  operator had withdrawn. The child environment was not ours either: the MCP SDK
  merges the supplied mapping over a default inheriting `HOME`, `LOGNAME`,
  `PATH`, `SHELL`, `TERM` and `USER`, so naming three of them left the
  operator's shell leaking in and made a README claim false. A fifth finding,
  that the response cap does not apply to stdio, is documented as a limit rather
  than papered over.
- **[#14](https://github.com/himanshu748/airlock-mcp/pull/14)** caught the
  README overstating what the approval-gate test asserted, then caught the first
  fix, then caught the second. The final version builds the server and reads its
  real annotations. Checking that fix surfaced a hole nothing had flagged:
  because the decorators read from the annotation map, downgrading a tool there
  silently stopped it counting as destructive and nothing required it to be
  gated. Those three tools are now pinned.
- **[#12](https://github.com/himanshu748/airlock-mcp/pull/12)** adding CI
  immediately disproved a claim: the suite was reported passing while two tests
  failed on a clean machine, fixed in
  [#11](https://github.com/himanshu748/airlock-mcp/pull/11).

Every one of those was a claim that did not match observed behaviour, which is
what Airlock detects for a living.

302 tests, run on Python 3.13 in GitHub Actions on every push and pull request.

## Three minute script

| Time | On screen | Say |
|---|---|---|
| 0:00-0:25 | Landing page hero | An MCP server tells your agent which of its tools are read-only. Your harness decides when to pause based on that. Nothing checks whether it is true. |
| 0:25-1:05 | `/record`, the dishonest fixture case | Here is a server that lies. It declares `export_report` read-only. Airlock ran it and observed it writing to disk. Declared and observed, side by side, with the evidence attached. Also a tool reaching outside the scope manifest, and a planted canary appearing in a sink. |
| 1:05-1:35 | Switch to the `server-memory` case | Same tool against a widely used public server. Nine tools probed, zero findings, and 39 of 54 checks marked not tested, because transcript-only evidence has no sensors to establish them. It names what it could not test instead of padding the count. |
| 1:35-2:15 | TrueForge agent spec and an approval card | A TrueForge agent drives the whole audit. `probe_tool`, `seal_case` and `emit_policy` are gated, because those exercise a live server or publish a policy, and the approval must never resolve from the server's own hints. |
| 2:15-2:45 | Terminal: blocked tool call | Enforcement is on the wire. An agent allowed every tool calls one the case did not approve and gets `MCP error -32001` from the proxy. Not a refusal it can argue with. |
| 2:45-3:00 | Disclaimer line | Airlock reports what it observed. Absence of a finding is not proof of safety. It will not tell you a server is safe, because it cannot know that. |

**Open on the lie being caught.** The `readOnlyHint: true` against an observed
filesystem write is the single clearest thirty seconds this project has.
