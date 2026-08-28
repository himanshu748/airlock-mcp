import type { CaseDetail, CaseSummary } from "./types";

// The interface is served from the same origin as the backend, so these are
// same-origin absolute paths. No CORS, no configured base URL to get wrong.
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

export function listCases(): Promise<{ cases: CaseSummary[] }> {
  return getJson("/api/cases");
}

export function readCase(caseId: string): Promise<CaseDetail> {
  return getJson(`/api/cases/${encodeURIComponent(caseId)}`);
}
