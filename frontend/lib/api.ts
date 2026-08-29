import type { CaseDetail, CaseSummary } from "./types";

// The interface is served from the same origin as the backend, so these are
// same-origin absolute paths. No CORS, no configured base URL to get wrong.
//
// The hosted build has no backend behind it: Airlock keeps signed case state
// on disk, runs audits past any serverless request budget and launches stdio
// servers as child processes, none of which survive a static host. So when
// /api is absent the interface reads a captured snapshot of a real audit
// instead, and says so rather than looking live.
export const SNAPSHOT_PATH = "/snapshot";

let snapshotMode = false;

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
  if (!snapshotMode) {
    try {
      return await getJson<T>(path);
    } catch {
      // Fall through to the snapshot rather than failing the page.
    }
  }
  const value = await getJson<T>(snapshotPath);
  snapshotMode = true;
  return value;
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
