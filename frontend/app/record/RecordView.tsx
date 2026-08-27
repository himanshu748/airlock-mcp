"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { listCases, readCase } from "@/lib/api";
import type { CaseDetail, CaseSummary } from "@/lib/types";
import { VERDICT_RANK, formatTimestamp, humanise, verdictOf } from "@/lib/verdict";
import { Stamp } from "@/components/Stamp";
import { Wordmark } from "@/components/Wordmark";
import { ToolRow } from "@/components/ToolRow";
import { DISCLAIMER, DisclaimerBar } from "../Disclaimer";

type LoadState = "loading" | "ready" | "empty" | "error";

export function RecordView() {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  const [message, setMessage] = useState("");
  const stampedOnce = useRef<Set<string>>(new Set());

  const select = useCallback(async (caseId: string) => {
    try {
      const next = await readCase(caseId);
      setDetail(next);
      setState("ready");
      window.history.replaceState(null, "", `#${caseId}`);
    } catch (error) {
      setDetail(null);
      setState("error");
      setMessage(error instanceof Error ? error.message : String(error));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { cases: found } = await listCases();
        if (cancelled) return;
        setCases(found);
        if (found.length === 0) {
          setState("empty");
          return;
        }
        const requested = window.location.hash.replace("#", "");
        const initial = found.some((item) => item.case_id === requested)
          ? requested
          : found[0].case_id;
        await select(initial);
      } catch (error) {
        if (cancelled) return;
        setState("error");
        setMessage(error instanceof Error ? error.message : String(error));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [select]);

  const animate = detail ? !stampedOnce.current.has(detail.case_id) : false;
  if (detail) stampedOnce.current.add(detail.case_id);

  return (
    <div className="min-h-screen">
      <header className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-4 border-b border-pencil-dim px-6 py-5 lg:px-10">
        <Wordmark tagline="inspection record" />
        {cases.length > 0 && (
          <label className="flex min-w-0 flex-1 items-baseline justify-end gap-2.5">
            <span className="label shrink-0">Case</span>
            <select
              aria-label="Select a case"
              value={detail?.case_id ?? ""}
              onChange={(event) => select(event.target.value)}
              className="min-w-0 max-w-full truncate border border-pencil-dim bg-desk px-2.5 py-1.5 font-mono text-[13px] text-form"
            >
              {cases.map((item) => (
                <option key={item.case_id} value={item.case_id}>
                  {item.case_id} · {item.target_url ?? "unreadable"} ·{" "}
                  {humanise(item.status)}
                </option>
              ))}
            </select>
          </label>
        )}
      </header>

      {state === "loading" && <Skeleton />}

      {state === "empty" && (
        <EmptyState>
          <p className="mb-3 text-[15px] leading-relaxed text-form">
            No cases on record yet.
          </p>
          <p className="max-w-[58ch] text-[15px] leading-relaxed text-pencil">
            Open one through the Airlock control MCP server with{" "}
            <code className="font-mono text-[13px] text-form">open_case</code>,
            then run the audit. This page reads whatever the case store holds.
          </p>
        </EmptyState>
      )}

      {state === "error" && (
        <EmptyState>
          <p className="mb-3 text-[15px] leading-relaxed text-stamp">
            Airlock could not read the case store.
          </p>
          <p className="max-w-[58ch] font-mono text-[13px] leading-relaxed text-pencil">
            {message}
          </p>
          <p className="mt-4 max-w-[58ch] text-[14px] leading-relaxed text-pencil">
            If the backend is running, check that the operator interface is
            enabled with{" "}
            <code className="font-mono text-[13px] text-form">
              AIRLOCK_ENABLE_OPERATOR_UI=true
            </code>
            .
          </p>
        </EmptyState>
      )}

      {state === "ready" && detail && (
        <Sheet detail={detail} animate={animate} />
      )}

      <DisclaimerBar text={detail?.disclaimer ?? DISCLAIMER} />
    </div>
  );
}

function Sheet({ detail, animate }: { detail: CaseDetail; animate: boolean }) {
  const byTool = new Map<string, CaseDetail["checks"]>();
  for (const check of detail.checks) {
    const list = byTool.get(check.tool) ?? [];
    list.push(check);
    byTool.set(check.tool, list);
  }

  // Divergence should be visible before you read a word, so the worst rows
  // sort to the top.
  const tools = [...detail.declared_tools].sort((a, b) => {
    const rank =
      VERDICT_RANK[verdictOf(byTool.get(a.name) ?? [])] -
      VERDICT_RANK[verdictOf(byTool.get(b.name) ?? [])];
    return rank !== 0 ? rank : a.name.localeCompare(b.name);
  });

  const tally = { BLOCKED: 0, HOLD: 0, CLEARED: 0 };
  for (const tool of tools) tally[verdictOf(byTool.get(tool.name) ?? [])] += 1;

  const capabilities = detail.observation_capabilities ?? {};
  const present = Object.keys(capabilities).filter((key) => capabilities[key]);
  const absent = Object.keys(capabilities).filter((key) => !capabilities[key]);

  return (
    <>
      <section className="border-b border-pencil-dim bg-desk px-6 py-6 lg:px-10">
        <dl className="grid grid-cols-[repeat(auto-fit,minmax(190px,1fr))] gap-x-7 gap-y-4">
          <Field label="Target" value={detail.target_url ?? "unknown"} />
          <Field label="Status" value={humanise(detail.status)} />
          <Field
            label="Evidence mode"
            value={humanise(detail.evidence_mode ?? "unknown")}
          />
          <Field
            label="Probes"
            value={
              detail.probe_budget
                ? `${detail.probes_run} of ${detail.probe_budget}`
                : String(detail.probes_run ?? 0)
            }
          />
          <Field
            label="Protocol"
            value={detail.protocol_version ?? "not inventoried"}
          />
          <Field label="Audited" value={formatTimestamp(detail.audited_at)} />
        </dl>

        <div className="mt-6 flex flex-wrap items-center gap-4">
          {(["BLOCKED", "HOLD", "CLEARED"] as const)
            .filter((verdict) => tally[verdict] > 0)
            .map((verdict) => (
              <span key={verdict} className="flex items-center gap-2">
                <Stamp
                  verdict={verdict}
                  caseId={detail.case_id}
                  auditedAt=""
                  size="sm"
                />
                <span className="font-mono text-[12px] text-pencil">
                  {tally[verdict]} {tally[verdict] === 1 ? "tool" : "tools"}
                </span>
              </span>
            ))}
        </div>

        <p className="mt-5 font-mono text-[13px] leading-relaxed text-pencil">
          sensors present: {present.map(humanise).join(", ") || "none"} · no
          sensor: {absent.map(humanise).join(", ") || "none"}
        </p>
      </section>

      <div className="sticky top-0 z-10 hidden grid-cols-[minmax(0,1fr)_1px_minmax(0,1fr)] border-b border-pencil-dim bg-slate px-6 lg:grid lg:px-10">
        <h2 className="label py-3.5">Declared by the server</h2>
        <div aria-hidden="true" />
        <h2 className="label py-3.5 pl-9">Observed by Airlock</h2>
      </div>

      <main>
        {tools.length === 0 ? (
          <EmptyState>
            <p className="text-[15px] leading-relaxed text-pencil">
              This case has no inventoried tools yet. Run the audit to populate
              it.
            </p>
          </EmptyState>
        ) : (
          tools.map((tool) => (
            <ToolRow
              key={tool.name}
              tool={tool}
              checks={byTool.get(tool.name) ?? []}
              caseId={detail.case_id}
              auditedAt={detail.audited_at}
              animate={animate}
            />
          ))
        )}
      </main>
    </>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="label mb-1.5">{label}</dt>
      <dd className="font-mono text-[13px] leading-relaxed break-words">
        {value}
      </dd>
    </div>
  );
}

function EmptyState({ children }: { children: React.ReactNode }) {
  return <div className="px-6 py-16 lg:px-10">{children}</div>;
}

function Skeleton() {
  return (
    <div className="px-6 py-16 lg:px-10" aria-live="polite" aria-busy="true">
      <p className="label mb-6">Reading the case store</p>
      <div className="space-y-3">
        {[0, 1, 2].map((row) => (
          <div key={row} className="h-3 max-w-[420px] bg-desk-2" />
        ))}
      </div>
      <span className="sr-only">Loading cases</span>
    </div>
  );
}
