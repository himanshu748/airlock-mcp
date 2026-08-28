import type { Check, StampVerdict, Tone } from "./types";

export const CHECK_ORDER = [
  "annotation_divergence",
  "undeclared_egress",
  "canary_exfiltration",
  "scope_escape",
  "injected_instructions",
  "schema_drift",
];

/**
 * A check is only clear when a sensor actually observed it.
 *
 * A check that no sensor in this case could observe gets its own neutral tone.
 * It is never shown as a pass, and it never drives the verdict on its own,
 * because in transcript-only mode that would stamp HOLD on every tool and make
 * the word meaningless. It is stated plainly in the row instead. This mirrors
 * minimum_approval_tools in airlock/approval.py.
 */
export function toneOf(check: Check): Tone {
  if (check.status === "finding") {
    return check.verdict === "suspicious" ? "hold" : "finding";
  }
  if (check.status === "no_finding_observed") return "clear";
  if (check.status === "not_tested" && check.sensor === "capability_absent") {
    return "none";
  }
  return "hold";
}

/**
 * A tool with no recorded checks has not been audited. Falling through to
 * CLEARED would stamp an affirmative verdict on a case that is still
 * inventoried or probing, which is exactly the overclaiming the report
 * language forbids. CLEARED requires a complete matrix that a sensor filled in.
 */
export function verdictOf(checks: Check[]): StampVerdict {
  if (checks.length === 0) return "NOT AUDITED";
  const tones = checks.map(toneOf);
  if (tones.includes("finding")) return "BLOCKED";
  if (tones.includes("hold")) return "HOLD";
  if (tones.every((tone) => tone === "none")) return "NOT AUDITED";
  return "CLEARED";
}

export const VERDICT_RANK: Record<StampVerdict, number> = {
  BLOCKED: 0,
  HOLD: 1,
  "NOT AUDITED": 2,
  CLEARED: 3,
};

export const TONE_GLYPH: Record<Tone, string> = {
  finding: "✕",
  hold: "▲",
  clear: "✓",
  none: "-",
};

export function stampGlyph(verdict: StampVerdict): string {
  if (verdict === "BLOCKED") return "✕";
  if (verdict === "HOLD") return "▲";
  if (verdict === "NOT AUDITED") return "?";
  return "✓";
}

/** Plain words. Never "potential security risk detected". */
export function statusWord(check: Check): string {
  if (check.status === "finding") return check.verdict ?? "finding";
  if (check.status === "no_finding_observed") return "no finding observed";
  if (check.status === "sensor_failed") return "sensor failed";
  if (check.sensor === "capability_absent") return "no sensor for this check";
  return "not tested";
}

export function humanise(value: string): string {
  return value.replace(/_/g, " ");
}

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "not audited";
  return value.replace("T", " ").slice(0, 19) + " UTC";
}
