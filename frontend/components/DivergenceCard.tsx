import { Stamp } from "./Stamp";

/** The product in one frame: the claim on the left, what happened on the right. */
export function DivergenceCard() {
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between gap-4 border-b border-pencil-dim/40 px-5 py-3">
        <span className="font-mono text-[12px] text-pencil">
          case af_5384c433 · acme-docs.example
        </span>
        <span className="font-mono text-[12px] text-pencil">
          controlled fixture · 24 probes
        </span>
      </div>

      <div className="grid lg:grid-cols-[minmax(0,1fr)_1px_minmax(0,1fr)]">
        <div className="px-5 py-6">
          <p className="label mb-3">Declared by the server</p>
          <pre className="paper overflow-x-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed">
            <code>{`"name": "summarize_documents"
"annotations": {
  "readOnlyHint": true
}`}</code>
          </pre>
          <p className="mt-3 font-mono text-[12px] text-pencil">
            the harness reads this and does not pause
          </p>
        </div>

        <div aria-hidden="true" className="hidden bg-pencil-dim/60 lg:block" />

        <div className="border-t border-pencil-dim/40 px-5 py-6 lg:border-t-0">
          <p className="label mb-3">Observed by Airlock</p>
          <ul className="mb-5 space-y-0">
            {[
              ["annotation divergence", "claimed read-only, wrote to disk"],
              ["canary exfiltration", "a planted value left the building"],
            ].map(([check, note]) => (
              <li
                key={check}
                className="grid grid-cols-[16px_minmax(0,1fr)] gap-x-2.5 border-t hairline py-2.5 first:border-t-0 first:pt-0"
              >
                <span aria-hidden="true" className="text-center font-mono text-[12px] leading-5 text-stamp">
                  ✕
                </span>
                <span className="font-display text-[10px] leading-5 font-bold tracking-[0.14em] uppercase text-stamp">
                  {check}
                </span>
                <span className="col-start-2 mt-0.5 text-[13.5px] leading-relaxed text-pencil">
                  {note}
                </span>
              </li>
            ))}
          </ul>
          <Stamp verdict="BLOCKED" caseId="af_5384c433" auditedAt="observed, not assumed" />
        </div>
      </div>
    </div>
  );
}
