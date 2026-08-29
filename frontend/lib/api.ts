import type { CaseDetail, CaseSummary } from "./types";

// The interface is served from the same origin as the backend, so these are
// same-origin absolute paths. No CORS, no configured base URL to get wrong.
//
// The hosted build has no backend behind it: Airlock keeps signed case state
// on disk, runs audits past any serverless request budget and launches stdio
// servers as child processes, none of which survive a static host. Its build
// explicitly selects a captured snapshot. The live build never turns an API
// outage or authorization failure into unrelated fixture data.
const UI_BASE_PATH = process.env.NEXT_PUBLIC_AIRLOCK_UI_BASE_PATH ?? "/ui";
export const SNAPSHOT_PATH = `${UI_BASE_PATH}/snapshot`;

const snapshotMode = process.env.NEXT_PUBLIC_AIRLOCK_SNAPSHOT_MODE === "true";

export function isSnapshot(): boolean {
  return snapshotMode;
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Airlock returned HTTP ${response.status} for ${path}`);
  }
  return (await response.json()) as T;
}

async function getJsonOrSnapshot<T>(
  path: string,
  snapshotPath: string,
): Promise<T> {
  if (snapshotMode) {
    return getJson<T>(snapshotPath);
  }
  return getJson<T>(path);
}

export function listCases(): Promise<{ cases: CaseSummary[] }> {
  return getJsonOrSnapshot("/api/cases", `${SNAPSHOT_PATH}/cases.json`);
}

export function readCase(caseId: string): Promise<CaseDetail> {
  const encoded = encodeURIComponent(caseId);
  return getJsonOrSnapshot(
    `/api/cases/${encoded}`,
    `${SNAPSHOT_PATH}/cases/${encoded}.json`,
  );
}
