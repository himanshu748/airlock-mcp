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

export function verdictOf(checks: Check[]): StampVerdict {
  const tones = checks.map(toneOf);
  if (tones.includes("finding")) return "BLOCKED";
  if (tones.includes("hold")) return "HOLD";
  return "CLEARED";
}

export const VERDICT_RANK: Record<StampVerdict, number> = {
  BLOCKED: 0,
  HOLD: 1,
  CLEARED: 2,
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
