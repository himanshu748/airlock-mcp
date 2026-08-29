type Audit = {
  name: string;
  target: string;
  mine: boolean;
  tools: number;
  probes: number;
  annotations: string;
  annotationTone: "stamp" | "cleared";
  headline: string;
  detail: string;
  result: string;
};

const AUDITS: Audit[] = [
  {
    name: "ContextFirewall",
    target: "himanshukumarjha-contextfirewall.hf.space/mcp/",
    mine: false,
    tools: 6,
    probes: 30,
    annotations: "None declared",
    annotationTone: "stamp",
    headline: "Six tools, no annotations at all.",
    detail:
      "Two of them are remember and forget_memory. A harness resolving @write and @destructive matches nothing here, so neither one earns an approval card. The fixture on this page shows a server that lies. This is a real server that simply says nothing, and silence defeats the selector the same way.",
    result: "0 findings. 24 of 36 checks not tested.",
  },
  {
    name: "Airlock control MCP",
    target: "127.0.0.1:8100/airlock-control/mcp",
    mine: true,
    tools: 6,
    probes: 11,
    annotations: "Complete on all six",
    annotationTone: "cleared",
    headline: "Airlock could not finish auditing itself.",
    detail:
      "Every tool declares its hints, and probe_tool, seal_case and emit_policy all carry destructiveHint. Then the probe planner refused open_case: its schema uses a $ref into $defs, which the v1 profile rejects. The boundary this project documents turns out to bite on its own front door.",
    result: "Case incomplete. The planner reported sensor_failed rather than a clean pass.",
  },
];

const STDIO_SERVERS: [string, string][] = [
  ["@modelcontextprotocol/server-filesystem", "14 tools"],
  ["@modelcontextprotocol/server-everything", "13 tools"],
  ["mcp-server-git", "12 tools"],
  ["@modelcontextprotocol/server-memory", "9 tools"],
  ["@modelcontextprotocol/server-sequential-thinking", "1 tool"],
];

export function StdioBreadth() {
  return (
    <div className="card p-6 lg:p-8">
      <p className="label mb-5">Also audited, launched as commands</p>
      <ul className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
        {STDIO_SERVERS.map(([name, tools]) => (
          <li
            key={name}
            className="flex items-baseline justify-between gap-4 border-b border-pencil-dim/30 pb-2.5"
          >
            <span className="font-mono text-[13px] break-all text-form">
              {name}
            </span>
            <span className="shrink-0 font-mono text-[12.5px] text-pencil">
              {tools}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-6 text-[14px] leading-relaxed text-pencil">
        Most MCP servers ship as a command rather than a URL, so Airlock can
        launch one and audit it the same way. The command comes from operator
        configuration, never from a case or a model, because running an audited
        server means executing the code the audit exists to distrust.
      </p>
    </div>
  );
}

export function RealAudits() {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {AUDITS.map((audit) => (
        <article key={audit.name} className="card flex flex-col p-6">
          <div className="mb-5 flex items-start justify-between gap-4">
            <div>
              <h3 className="font-display text-[15px] font-bold tracking-[0.04em] uppercase">
                {audit.name}
              </h3>
              <p className="mt-2 font-mono text-[12px] break-all text-pencil">
                {audit.target}
              </p>
            </div>
            <span className="label shrink-0">
              {audit.mine ? "self audit" : "third party"}
            </span>
          </div>

          <dl className="mb-5 grid grid-cols-3 gap-3 border-y border-pencil-dim/40 py-4">
            <div>
              <dt className="label mb-1.5">Tools</dt>
              <dd className="font-mono text-[15px] text-form">{audit.tools}</dd>
            </div>
            <div>
              <dt className="label mb-1.5">Probes</dt>
              <dd className="font-mono text-[15px] text-form">{audit.probes}</dd>
            </div>
            <div>
              <dt className="label mb-1.5">Annotations</dt>
              <dd
                className={`font-mono text-[13px] ${
                  audit.annotationTone === "stamp"
                    ? "text-stamp"
                    : "text-cleared"
                }`}
              >
                {audit.annotations}
              </dd>
            </div>
          </dl>

          <h4 className="mb-2.5 font-display text-[17px] leading-snug font-bold tracking-[-0.01em]">
            {audit.headline}
          </h4>
          <p className="text-[14px] leading-relaxed text-pencil">
            {audit.detail}
          </p>

          <p className="mt-auto pt-5 font-mono text-[12.5px] text-form">
            {audit.result}
          </p>
        </article>
      ))}
    </div>
  );
}
