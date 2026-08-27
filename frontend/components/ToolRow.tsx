import type { Check, DeclaredTool } from "@/lib/types";
import {
  CHECK_ORDER,
  TONE_GLYPH,
  formatTimestamp,
  humanise,
  statusWord,
  toneOf,
  verdictOf,
} from "@/lib/verdict";
import { Stamp } from "./Stamp";

const TONE_TEXT = {
  finding: "text-stamp",
  hold: "text-hold",
  clear: "text-cleared",
  none: "text-pencil",
} as const;

/**
 * Everything rendered here originates with the server under audit. React
 * escapes it by construction: no dangerouslySetInnerHTML anywhere in this app.
 */
export function ToolRow({
  tool,
  checks,
  caseId,
  auditedAt,
  animate,
}: {
  tool: DeclaredTool;
  checks: Check[];
  caseId: string;
  auditedAt: string | null | undefined;
  animate: boolean;
}) {
  const verdict = verdictOf(checks);
  const annotations = Object.keys(tool.annotations ?? {}).sort();
  const properties = Object.keys(
    (tool.input_schema?.properties as Record<string, unknown>) ?? {},
  ).sort();
  const ordered = [...checks].sort(
    (a, b) => CHECK_ORDER.indexOf(a.check) - CHECK_ORDER.indexOf(b.check),
  );

  return (
    <article className="grid border-b hairline lg:grid-cols-[minmax(0,1fr)_1px_minmax(0,1fr)]">
      {/* Left: what the server declared, verbatim, in its own words. */}
      <div className="px-6 py-8 lg:px-10">
        <h3 className="mb-4 font-mono text-[15px] font-medium break-words text-form">
          {tool.name}
        </h3>

        <div className="mb-4 flex flex-wrap gap-2">
          {annotations.length === 0 ? (
            <span className="border border-pencil-dim px-2 py-1.5 font-mono text-[12px] text-pencil">
              no annotations published
            </span>
          ) : (
            annotations.map((key) => {
              const value = tool.annotations[key];
              const asserted = value === true;
              return (
                <span
                  key={key}
                  className={[
                    "border px-2 py-1.5 font-mono text-[12px]",
                    asserted
                      ? "border-form text-form"
                      : "border-pencil-dim text-pencil",
                  ].join(" ")}
                >
                  {key}: {String(value)}
                </span>
              );
            })
          )}
        </div>

        <p className="paper px-4 py-3 font-mono text-[13px] leading-relaxed break-words">
          {tool.description || (
            <span className="text-pencil">
              (the server published no description)
            </span>
          )}
        </p>

        <p className="mt-3 font-mono text-[12px] text-pencil">
          declared parameters:{" "}
          {properties.length ? properties.join(", ") : "none"}
        </p>
      </div>

      <div aria-hidden="true" className="hidden bg-pencil-dim lg:block" />

      {/* Right: what Airlock observed. */}
      <div className="border-t hairline px-6 py-8 lg:border-t-0 lg:px-10">
        <div className="mb-6">
          <Stamp
            verdict={verdict}
            caseId={caseId}
            auditedAt={formatTimestamp(auditedAt)}
            animate={animate}
          />
        </div>

        <ul className="space-y-0">
          {ordered.map((check) => {
            const tone = toneOf(check);
            return (
              <li
                key={check.check}
                className="grid grid-cols-[18px_minmax(0,1fr)] gap-x-2.5 border-t hairline py-2.5 first:border-t-0 first:pt-0"
              >
                <span
                  aria-hidden="true"
                  className={`text-center font-mono text-[13px] leading-6 ${TONE_TEXT[tone]}`}
                >
                  {TONE_GLYPH[tone]}
                </span>
                <span
                  className={`font-display text-[10px] leading-6 font-bold tracking-[0.14em] uppercase ${TONE_TEXT[tone]}`}
                >
                  {humanise(check.check)}: {statusWord(check)}
                </span>
                <p className="col-start-2 mt-0.5 text-[14px] leading-relaxed break-words text-pencil">
                  {check.explanation}
                </p>
              </li>
            );
          })}
        </ul>

        <p className="mt-4 font-mono text-[12px] text-pencil">
          {tool.probes_run} {tool.probes_run === 1 ? "probe" : "probes"} run
        </p>
      </div>
    </article>
  );
}
