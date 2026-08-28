import Link from "next/link";
import { SiteNav } from "@/components/SiteNav";
import { Section } from "@/components/Section";
import { DivergenceCard } from "@/components/DivergenceCard";
import { RunProof } from "@/components/RunProof";
import { Reveal } from "@/components/Reveal";
import { DISCLAIMER } from "./Disclaimer";

const STATS = [
  ["5 of 5", "planted behaviours detected in the dishonest fixture"],
  ["0", "findings on the honest fixture, across 36 checks"],
  ["6", "detections, each reported as a verdict and never a score"],
  ["24", "probes to audit a six-tool server end to end"],
];

const STEPS = [
  {
    n: "01",
    title: "Point it at a server",
    body: "Give Airlock a URL you are considering connecting. It validates the target, resolves the hostname once and pins that address for every connection the case makes afterwards.",
  },
  {
    n: "02",
    title: "Read the declaration",
    body: "One tools/list call captures every tool, description, schema and annotation. That is the claim under test, recorded verbatim.",
  },
  {
    n: "03",
    title: "Exercise and probe",
    body: "Generated inputs, then adversarial ones: boundary values, path-shaped strings, planted canaries. Rate limited, capped, and only ever pointed at a target you submitted.",
  },
  {
    n: "04",
    title: "Decide, then enforce",
    body: "Declarations and observations land side by side and stop for your decision. On approval Airlock emits a connector policy and the proxy holds it.",
  },
];

const CHECKS = [
  {
    name: "Annotation divergence",
    signal: "A tool annotated read-only performed a write or a state change.",
    verdict: "Block",
    tone: "stamp",
  },
  {
    name: "Canary exfiltration",
    signal: "A planted value appeared in an outbound request or in another tool's output.",
    verdict: "Critical",
    tone: "stamp",
  },
  {
    name: "Undeclared egress",
    signal: "The server reached a host outside its declared scope. Needs a sensor that can see the server's own network.",
    verdict: "Block",
    tone: "stamp",
  },
  {
    name: "Scope escape",
    signal: "File paths touched outside the declared directory.",
    verdict: "Critical",
    tone: "stamp",
  },
  {
    name: "Injected instructions",
    signal: "A tool result carried imperative text addressed to the model.",
    verdict: "Suspicious",
    tone: "hold",
  },
  {
    name: "Schema drift",
    signal: "A tool accepted parameters that are not in its published schema.",
    verdict: "Suspicious",
    tone: "hold",
  },
];

const POLICY = `{
  "mcp_servers": [
    {
      "name": "acme-docs-via-airlock",
      "enable_tools": ["search_docs", "get_document"],
      "disable_tools": ["export_report"],
      "require_approval_for_tools": ["create_ticket"],
      "preload": false
    }
  ]
}`;

const FAQ = [
  [
    "Does this replace my harness's approval gate?",
    "No. The harness enforces a policy; it does not verify the claims that policy is derived from. Airlock produces that input. The two are complementary, and Airlock reimplements none of the sandboxing, approvals or tool filters the harness already provides.",
  ],
  [
    "What happens to a tool that lied?",
    "It is moved into require_approval_for_tools by name rather than by selector, because the selector cannot be trusted for that server. Naming it is the whole product.",
  ],
  [
    "Can a hostile server attack the auditor?",
    "Raw tool results are quarantined by the backend and never re-enter the model as text; the control MCP returns digests instead. Model and target credentials never enter the sandbox.",
  ],
  [
    "Will it tell me a server is fine?",
    "It will not. Airlock reports what it observed across a bounded number of probes, names the checks nothing could observe, and refuses to describe absence of a finding as a clean result.",
  ],
];

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      <SiteNav />
      <Reveal />

      {/* Hero */}
      <section className="hero-wash relative overflow-hidden px-6 pt-20 pb-24 lg:px-8 lg:pt-28 lg:pb-32">
        <div className="shell grid items-center gap-14 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)] lg:gap-16">
          <div>
            <span className="pill mb-7">
              <span aria-hidden="true" className="text-stamp">●</span>
              MCP connector auditing
            </span>

            <h1 className="max-w-[15ch] font-display text-[clamp(40px,6vw,68px)] leading-[1.02] font-bold tracking-[-0.025em]">
              The server says it&rsquo;s read&#8209;only.{" "}
              <span className="text-stamp">Prove it.</span>
            </h1>

            <p className="mt-7 max-w-[54ch] text-[17px] leading-relaxed text-pencil">
              Your agent harness pauses before sensitive tool calls. Which tools
              count as sensitive comes from the annotations the MCP server
              publishes about itself. Nothing in the protocol requires those to
              be true, and nothing in the client checks.
            </p>

            <p className="mt-4 max-w-[54ch] text-[17px] leading-relaxed text-pencil">
              Airlock exercises a server before you trust it and emits a
              connector policy built from what it observed.
            </p>

            <div className="mt-9 flex flex-wrap items-center gap-3">
              <Link href="/record/" className="btn btn-primary">
                Open the inspection record
              </Link>
              <a href="#how" className="btn btn-ghost">
                How it works
              </a>
            </div>

            <p className="mt-7 font-mono text-[12.5px] leading-relaxed text-pencil">
              Verified against a running TrueForge instance, not a mock.
            </p>
          </div>

          <DivergenceCard />
        </div>
      </section>

      {/* Stats */}
      <div className="rule-top px-6 py-12 lg:px-8">
        <dl className="shell grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {STATS.map(([figure, note]) => (
            <div key={note}>
              <dt className="font-display text-[30px] leading-none font-bold tracking-[-0.02em]">
                {figure}
              </dt>
              <dd className="mt-3 text-[14px] leading-relaxed text-pencil">
                {note}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {/* The gap */}
      <Section
        id="gap"
        eyebrow="The gap it closes"
        title="A safety gate is only as honest as the server describing itself."
        lede="require_approval_for_tools defaults to @write and @destructive. Those selectors resolve from annotations the server publishes. A server that labels export_report read-only runs it without the human ever seeing a pause."
      >
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="card p-6">
            <p className="label mb-4">What the harness is told</p>
            <pre className="paper overflow-x-auto px-4 py-3 font-mono text-[13px] leading-relaxed">
              <code>{`"require_approval_for_tools":
  ["@write", "@destructive"]`}</code>
            </pre>
            <p className="mt-4 text-[14.5px] leading-relaxed text-pencil">
              Resolved from the server&rsquo;s own annotations. Never verified.
            </p>
          </div>
          <div className="card p-6">
            <p className="label mb-4">What Airlock adds</p>
            <pre className="paper overflow-x-auto px-4 py-3 font-mono text-[13px] leading-relaxed">
              <code>{`"require_approval_for_tools":
  ["export_report"]`}</code>
            </pre>
            <p className="mt-4 text-[14.5px] leading-relaxed text-pencil">
              Named literally, because the selector cannot be trusted for this
              server. That one line is the product.
            </p>
          </div>
        </div>
      </Section>

      {/* How it works */}
      <Section
        id="how"
        eyebrow="How it works"
        title="Four passes, then a decision that belongs to you."
      >
        <ol className="grid gap-px border border-pencil-dim/40 bg-pencil-dim/40 md:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((step) => (
            <li key={step.n} className="bg-desk px-6 py-8">
              <p className="mb-5 font-mono text-[13px] text-stamp">{step.n}</p>
              <h3 className="mb-3 font-display text-[11px] font-bold tracking-[0.16em] uppercase">
                {step.title}
              </h3>
              <p className="text-[14px] leading-relaxed text-pencil">
                {step.body}
              </p>
            </li>
          ))}
        </ol>
      </Section>

      {/* Proof */}
      <Section
        id="run"
        eyebrow="See it run"
        title="One command, against a server that lies on purpose."
        lede="The repository ships two owned fixtures with the same six-tool shape. One declares itself accurately. The other plants five behaviours behind honest-looking annotations. This is the real output of auditing the second one."
      >
        <RunProof />
      </Section>

      {/* Checks */}
      <Section
        id="checks"
        eyebrow="What it looks for"
        title="Six checks. Verdicts, never a risk score."
        lede="Suspicious is a real verdict, not a hedge: it means a human should look, and the approval card says exactly that. A check no sensor in a case can observe is reported as exactly that, never folded in with the clean results."
      >
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {CHECKS.map((check) => (
            <article key={check.name} className="card card-hover p-6">
              <div className="mb-4 flex items-center justify-between gap-3">
                <span
                  aria-hidden="true"
                  className={`font-mono text-[13px] ${
                    check.tone === "stamp" ? "text-stamp" : "text-hold"
                  }`}
                >
                  {check.tone === "stamp" ? "✕" : "▲"}
                </span>
                <span
                  className={`border border-current px-2 py-1 font-display text-[9.5px] font-bold tracking-[0.12em] uppercase ${
                    check.tone === "stamp" ? "text-stamp" : "text-hold"
                  }`}
                >
                  {check.verdict}
                </span>
              </div>
              <h3 className="mb-2.5 font-mono text-[14.5px] font-medium">
                {check.name}
              </h3>
              <p className="text-[14px] leading-relaxed text-pencil">
                {check.signal}
              </p>
            </article>
          ))}
        </div>
      </Section>

      {/* Output */}
      <Section
        id="output"
        eyebrow="The output"
        title="A file you paste, not an opinion you weigh."
        lede="Airlock emits a connector policy and a downloadable evidence report. The proxy stays in front of the server afterwards and enforces exactly what you approved."
      >
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
          <div className="card overflow-hidden">
            <div className="border-b border-pencil-dim/40 px-5 py-3">
              <span className="font-mono text-[12px] text-pencil">
                airlock-policy.json
              </span>
            </div>
            <pre className="overflow-x-auto px-5 py-5 font-mono text-[13px] leading-relaxed">
              <code>{POLICY}</code>
            </pre>
          </div>

          <div className="grid gap-4">
            {[
              [
                "Enforced, not advisory",
                "Register the proxy rather than the server. A tool you denied is refused on the wire, not merely hidden from the model.",
              ],
              [
                "Evidence you can read",
                "airlock-report.json carries every probe, observation and finding, with the raw suspect bodies left out.",
              ],
              [
                "No policy without a decision",
                "Emission requires a recorded human choice. There is no path that approves a connector on the agent's own say-so.",
              ],
            ].map(([title, body]) => (
              <div key={title} className="card card-hover p-5">
                <h3 className="mb-2 font-display text-[11px] font-bold tracking-[0.14em] uppercase">
                  {title}
                </h3>
                <p className="text-[14px] leading-relaxed text-pencil">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* FAQ */}
      <Section eyebrow="Questions" title="What Airlock does and does not claim.">
        <div className="grid gap-px border border-pencil-dim/40 bg-pencil-dim/40 md:grid-cols-2">
          {FAQ.map(([q, a]) => (
            <div key={q} className="bg-desk px-6 py-7">
              <h3 className="mb-3 font-mono text-[14.5px] font-medium">{q}</h3>
              <p className="text-[14px] leading-relaxed text-pencil">{a}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Closing */}
      <section className="rule-top px-6 py-20 lg:px-8 lg:py-24">
        <div className="shell">
          <h2 className="max-w-[20ch] font-display text-[clamp(26px,3.4vw,40px)] leading-[1.1] font-bold tracking-[-0.015em]">
            Audit a connector before you trust it.
          </h2>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link href="/record/" className="btn btn-primary">
              Open the inspection record
            </Link>
          </div>
        </div>
      </section>

      <footer className="rule-top px-6 py-10 lg:px-8">
        <div className="shell flex flex-wrap items-baseline justify-between gap-4">
          <p className="font-mono text-[13px] leading-relaxed text-form">
            {DISCLAIMER}
          </p>
          <p className="font-mono text-[12px] text-pencil">
            Agent Harness Hackathon · WeMakeDevs x TrueFoundry
          </p>
        </div>
      </footer>
    </div>
  );
}
