import Link from "next/link";
import { Wordmark } from "@/components/Wordmark";
import { Stamp } from "@/components/Stamp";
import { DISCLAIMER } from "./Disclaimer";

const PASSES = [
  {
    n: "01",
    title: "Declaration",
    body: "Record every tool, description, schema and annotation. This is the claim under test.",
  },
  {
    n: "02",
    title: "Exercise",
    body: "Call each tool through a recording proxy with generated inputs, and record what came back.",
  },
  {
    n: "03",
    title: "Probe",
    body: "Adversarial inputs, rate limited and capped, pointed only at a target you submitted.",
  },
  {
    n: "04",
    title: "Verdict",
    body: "Join the declarations to the observations, then stop for your decision.",
  },
];

const CHECKS = [
  ["Annotation divergence", "A read-only tool changed state", "Block", "finding"],
  ["Undeclared egress", "A request to a host outside declared scope", "Block", "finding"],
  ["Canary exfiltration", "A planted value left in an outbound request", "Critical", "finding"],
  ["Scope escape", "Paths touched outside the declared directory", "Critical", "finding"],
  ["Injected instructions", "A result carrying imperatives aimed at the model", "Suspicious", "hold"],
  ["Schema drift", "Arguments accepted outside the published schema", "Suspicious", "hold"],
] as const;

const POLICY = `{
  "mcp_servers": [
    {
      "name": "acme-docs-via-airlock",
      "enable_tools": ["search_docs", "get_document"],
      "disable_tools": ["export_report"],
      "require_approval_for_tools": ["create_ticket", "delete_cache"],
      "preload": false
    }
  ]
}`;

const DECLARATION = `"name": "summarize_documents"
"annotations": {
  "readOnlyHint": true
}`;

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      <header className="flex flex-wrap items-baseline justify-between gap-6 border-b border-pencil-dim px-6 py-5 lg:px-10">
        <Wordmark tagline="connector inspection" />
        <Link
          href="/record/"
          className="border-b border-pencil pb-0.5 font-mono text-[13px] text-form no-underline transition-colors hover:border-form"
        >
          Open the inspection record
        </Link>
      </header>

      {/* Hero */}
      <section className="grain relative border-b border-pencil-dim px-6 py-20 lg:px-10 lg:py-28">
        <p className="label mb-6">MCP connector auditing</p>
        <h1 className="mb-8 max-w-[17ch] font-display text-[clamp(38px,6.4vw,76px)] leading-[1.02] font-bold tracking-[-0.02em]">
          The server says it&rsquo;s read&#8209;only.{" "}
          <span className="text-stamp">Prove it.</span>
        </h1>
        <div className="max-w-[62ch] space-y-4">
          <p className="text-[clamp(15px,1.5vw,17px)] leading-relaxed text-pencil">
            Your agent harness pauses for human approval before sensitive tool
            calls. Which tools count as sensitive is resolved from the
            annotations the MCP server publishes about itself. Nothing in the
            protocol requires those annotations to be true, and nothing in the
            client checks.
          </p>
          <p className="text-[clamp(15px,1.5vw,17px)] leading-relaxed text-pencil">
            Airlock exercises a server&rsquo;s tools before you trust it,
            records what actually happened, and emits a connector policy built
            from the observation rather than the claim.
          </p>
        </div>
      </section>

      {/* The gap */}
      <section className="border-b border-pencil-dim px-6 py-16 lg:px-10 lg:py-20">
        <h2 className="label mb-8">The gap it closes</h2>
        <div className="grid gap-9 lg:grid-cols-[minmax(0,1fr)_1px_minmax(0,1fr)] lg:gap-0">
          <div className="lg:pr-9">
            <p className="label mb-4">What the server declares</p>
            <pre className="paper overflow-x-auto px-5 py-4 font-mono text-[13px] leading-relaxed">
              <code>{DECLARATION}</code>
            </pre>
            <p className="mt-4 font-mono text-[13px] leading-relaxed text-pencil">
              The harness reads this and does not pause.
            </p>
          </div>

          <div aria-hidden="true" className="hidden bg-pencil-dim lg:block" />

          <div className="border-t border-pencil-dim pt-9 lg:border-t-0 lg:pt-0 lg:pl-9">
            <p className="label mb-4">What Airlock observed</p>
            <ul className="mb-7">
              {[
                "Claimed read-only. Wrote to disk.",
                "A planted canary left the building.",
              ].map((line) => (
                <li
                  key={line}
                  className="grid grid-cols-[18px_minmax(0,1fr)] gap-2.5 border-t hairline py-2.5 text-[15px] leading-relaxed first:border-t-0"
                >
                  <span aria-hidden="true" className="text-center font-mono text-[13px] leading-6 text-stamp">
                    ✕
                  </span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
            <Stamp
              verdict="BLOCKED"
              caseId="af_…"
              auditedAt="observed, not assumed"
            />
          </div>
        </div>
      </section>

      {/* Four passes */}
      <section className="border-b border-pencil-dim px-6 py-16 lg:px-10 lg:py-20">
        <h2 className="label mb-8">Four passes</h2>
        <ol className="grid gap-px border border-pencil-dim bg-pencil-dim sm:grid-cols-2 lg:grid-cols-4">
          {PASSES.map((pass) => (
            <li key={pass.n} className="bg-desk px-6 py-7">
              <p className="mb-4 font-mono text-[13px] text-stamp">{pass.n}</p>
              <h3 className="mb-2.5 font-display text-[11px] font-bold tracking-[0.16em] uppercase">
                {pass.title}
              </h3>
              <p className="text-[14px] leading-relaxed text-pencil">
                {pass.body}
              </p>
            </li>
          ))}
        </ol>
      </section>

      {/* Checks */}
      <section className="border-b border-pencil-dim px-6 py-16 lg:px-10 lg:py-20">
        <h2 className="label mb-8">What it looks for</h2>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-[14px]">
            <thead>
              <tr>
                {["Check", "Signal", "Verdict on hit"].map((head) => (
                  <th
                    key={head}
                    scope="col"
                    className="label border-b border-pencil-dim py-3.5 pr-5 text-left"
                  >
                    {head}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {CHECKS.map(([name, signal, verdict, tone]) => (
                <tr key={name}>
                  <th
                    scope="row"
                    className="border-b hairline py-3.5 pr-5 text-left font-mono text-[14px] font-medium"
                  >
                    {name}
                  </th>
                  <td className="border-b hairline py-3.5 pr-5 text-pencil">
                    {signal}
                  </td>
                  <td className="border-b hairline py-3.5 pr-5">
                    <span
                      className={[
                        "inline-block border border-current px-2 py-1 font-display text-[10px] font-bold tracking-[0.12em] whitespace-nowrap uppercase",
                        tone === "finding" ? "text-stamp" : "text-hold",
                      ].join(" ")}
                    >
                      <span aria-hidden="true">
                        {tone === "finding" ? "✕" : "▲"}
                      </span>{" "}
                      {verdict}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-6 max-w-[62ch] font-mono text-[13px] leading-relaxed text-pencil">
          A check no sensor in a case can observe is reported as exactly that.
          It is never folded in with the clean results.
        </p>
      </section>

      {/* Artifact */}
      <section className="border-b border-pencil-dim px-6 py-16 lg:px-10 lg:py-20">
        <h2 className="label mb-8">The output is a file, not an opinion</h2>
        <p className="mb-7 max-w-[62ch] text-[15px] leading-relaxed text-pencil">
          Tools that contradicted their own annotations are moved into{" "}
          <code className="font-mono text-[13px] text-form">
            require_approval_for_tools
          </code>{" "}
          by name, because the selector cannot be trusted for this server. Paste
          it into your agent spec unedited.
        </p>
        <pre className="overflow-x-auto border border-pencil-dim bg-desk px-6 py-5 font-mono text-[13px] leading-relaxed">
          <code>{POLICY}</code>
        </pre>
        <p className="mt-6 max-w-[62ch] font-mono text-[13px] leading-relaxed text-pencil">
          The proxy stays in front of the server afterwards and enforces exactly
          what you approved.
        </p>
      </section>

      <footer className="grid gap-3.5 px-6 py-10 lg:px-10">
        <p className="font-mono text-[13px] leading-relaxed text-form">
          {DISCLAIMER}
        </p>
        <p>
          <Link
            href="/record/"
            className="border-b border-pencil pb-0.5 font-mono text-[13px] text-form no-underline transition-colors hover:border-form"
          >
            Open the inspection record
          </Link>
        </p>
      </footer>
    </div>
  );
}
