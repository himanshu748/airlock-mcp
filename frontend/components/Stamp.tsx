import type { StampVerdict } from "@/lib/types";
import { stampGlyph } from "@/lib/verdict";

const TONE: Record<StampVerdict, { color: string; tilt: string }> = {
  BLOCKED: { color: "text-stamp", tilt: "-3.5deg" },
  HOLD: { color: "text-hold", tilt: "2deg" },
  CLEARED: { color: "text-cleared", tilt: "-2.5deg" },
};

/**
 * The signature element. It lands once, settles in 120ms and does not bounce,
 * and it carries the case number and timestamp inside it like a real
 * inspection mark. Every verdict carries a word and a glyph, never colour
 * alone.
 */
export function Stamp({
  verdict,
  caseId,
  auditedAt,
  animate = false,
  size = "md",
}: {
  verdict: StampVerdict;
  caseId: string;
  auditedAt?: string;
  animate?: boolean;
  size?: "md" | "sm";
}) {
  const tone = TONE[verdict];
  const small = size === "sm";
  const shortId = caseId.startsWith("af_") ? `af_${caseId.slice(3, 11)}` : caseId;

  return (
    <div
      role="img"
      aria-label={`Verdict ${verdict} for case ${caseId}`}
      style={{ ["--tilt" as string]: tone.tilt, transform: `rotate(${tone.tilt})` }}
      className={[
        "inline-flex flex-col items-start border-2 border-current select-none",
        small ? "px-2.5 py-1.5" : "px-3.5 py-2.5",
        tone.color,
        animate ? "stamp-land" : "",
      ].join(" ")}
    >
      <span
        className={[
          "flex items-baseline gap-2 font-display font-bold uppercase whitespace-nowrap",
          small ? "text-[10px] tracking-[0.18em]" : "text-[13px] tracking-[0.2em]",
        ].join(" ")}
      >
        <span aria-hidden="true">{stampGlyph(verdict)}</span>
        {verdict}
      </span>

      {!small && (
        <span className="mt-1.5 font-mono text-[9px] leading-[1.45] tracking-wide opacity-75">
          <span className="block whitespace-nowrap">{shortId}</span>
          {auditedAt && (
            <span className="block whitespace-nowrap">{auditedAt}</span>
          )}
        </span>
      )}
    </div>
  );
}
