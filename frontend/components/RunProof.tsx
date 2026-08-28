const FINDINGS: {
  verdict: "block" | "critical" | "suspicious";
  check: string;
  tool: string;
  sensor: string;
}[] = [
  {
    verdict: "block",
    check: "annotation_divergence",
    tool: "tool_0001",
    sensor: "fixture_filesystem",
  },
  {
    verdict: "critical",
    check: "scope_escape",
    tool: "tool_0001",
    sensor: "fixture_filesystem",
  },
  {
    verdict: "block",
    check: "undeclared_egress",
    tool: "tool_0002",
    sensor: "fixture_network",
  },
  {
    verdict: "critical",
    check: "scope_escape",
    tool: "tool_0003",
    sensor: "fixture_filesystem",
  },
  {
    verdict: "suspicious",
    check: "injected_instructions",
    tool: "tool_0005",
    sensor: "mcp_transcript",
  },
  {
    verdict: "critical",
    check: "canary_exfiltration",
    tool: "tool_0006",
    sensor: "canary_sink",
  },
  {
    verdict: "critical",
    check: "scope_escape",
    tool: "tool_0006",
    sensor: "fixture_filesystem",
  },
];

const toneOf = (verdict: string) =>
  verdict === "suspicious" ? "text-hold" : "text-stamp";

export function RunProof() {
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between gap-3 border-b border-pencil-dim/40 px-5 py-3">
          <span className="font-mono text-[12px] text-pencil">
            scripts/demo_audit.py
          </span>
          <span className="label">dishonest fixture</span>
        </div>

        <div className="overflow-x-auto px-5 py-5 font-mono text-[13px] leading-relaxed">
          <p className="text-pencil">
            <span className="text-stamp">$</span> .venv/bin/python
            scripts/demo_audit.py --declared-root /workspace/documents
          </p>

          <p className="mt-4 text-form">declared tools: 6</p>
          <p className="text-pencil">probes run: 24</p>
          <p className="mt-3 text-form">
            findings: <span className="text-stamp">7</span> of 36 checks
          </p>

          <ul className="mt-4 space-y-1.5">
            {FINDINGS.map((finding, index) => (
              <li
                key={`${finding.check}-${finding.tool}-${index}`}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1"
              >
                <span
                  className={`${toneOf(finding.verdict)} w-[11ch] shrink-0`}
                >
                  [{finding.verdict}]
                </span>
                <span className="text-form">{finding.check}</span>
                <span className="text-pencil">{finding.tool}</span>
                <span className="text-pencil">{finding.sensor}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid content-start gap-4">
        <div className="card p-6">
          <p className="label mb-4">Same command, honest fixture</p>
          <p className="font-mono text-[13px] leading-relaxed text-form">
            findings: <span className="text-cleared">0</span> of 36 checks
          </p>
          <p className="mt-4 text-[14px] leading-relaxed text-pencil">
            The same six-tool shape, the same 36 checks, the same probe budget.
            The detectors fire on behaviour, not on a server being unfamiliar.
          </p>
        </div>

        <div className="card p-6">
          <p className="label mb-4">What tool_0001 declared</p>
          <pre className="paper overflow-x-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed">
            <code>{`"annotations": {
  "readOnlyHint": true
}`}</code>
          </pre>
          <p className="mt-4 text-[14px] leading-relaxed text-pencil">
            It wrote to disk during the probe. That single divergence is what a
            harness reading annotations cannot see, and it is why the emitted
            policy names the tool literally.
          </p>
        </div>

        <div className="card p-6">
          <p className="label mb-3">Reproduce it</p>
          <p className="text-[14px] leading-relaxed text-pencil">
            Both fixtures ship with the repository and run on loopback. The
            README carries the exact commands, and the run above is their real
            output.
          </p>
        </div>
      </div>
    </div>
  );
}
