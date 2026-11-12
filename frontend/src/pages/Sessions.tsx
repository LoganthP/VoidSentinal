import { Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { DemoTag, EmptyState, ErrorBanner, OutcomePill, PageHeader, ScoreBar, SeverityBadge, Skeleton, VerdictTag } from "../components/ui";
import { usePoll } from "../lib/api";
import { useScope } from "../lib/scope";
import { fmtDuration, fmtTime, OUTCOME } from "../lib/format";
import type { Session } from "../lib/types";

const PAGE = 50;

export default function Sessions() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [q, setQ] = useState(params.get("q") || "");

  // debounce search text into the URL
  useEffect(() => {
    const id = window.setTimeout(() => {
      const next = new URLSearchParams(params);
      if (q) next.set("q", q); else next.delete("q");
      next.delete("page");
      if (next.toString() !== params.toString()) setParams(next, { replace: true });
    }, 350);
    return () => window.clearTimeout(id);
  }, [q]); // eslint-disable-line react-hooks/exhaustive-deps

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next, { replace: true });
  };

  const { withScope } = useScope();
  const page = Number(params.get("page") || 0);
  const query = useMemo(() => {
    const p = new URLSearchParams();
    for (const k of ["q", "outcome", "verdict", "has_alert", "demo", "sort", "status"]) {
      const v = params.get(k); if (v) p.set(k, v);
    }
    p.set("limit", String(PAGE)); p.set("offset", String(page * PAGE));
    return withScope(`/sessions?${p.toString()}`);
  }, [params, page, withScope]);

  const { data, error, loading, reload } = usePoll<{ total: number; items: Session[] }>(query, 15000);

  const select = "field py-1.5 pr-8";
  return (
    <>
      <PageHeader title="SSH sessions" subtitle="Every SSH or Telnet connection Cowrie recorded, rebuilt from its events. Open one to see its timeline and record a verdict." />

      <div className="glass mb-4 flex flex-wrap items-center gap-2 p-3">
        <label className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
          <input className="field w-full pl-9" placeholder="Search source IP, username, session ID or command text"
                 value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search sessions" />
        </label>
        <select className={select} value={params.get("outcome") || ""} onChange={(e) => set("outcome", e.target.value)} aria-label="Outcome">
          <option value="">Any outcome</option>
          {Object.entries(OUTCOME).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <select className={select} value={params.get("has_alert") || ""} onChange={(e) => set("has_alert", e.target.value)} aria-label="Alerts">
          <option value="">With or without alerts</option>
          <option value="true">Has alerts</option>
          <option value="false">No alerts</option>
        </select>
        <select className={select} value={params.get("verdict") || ""} onChange={(e) => set("verdict", e.target.value)} aria-label="Verdict">
          <option value="">Any verdict</option>
          <option value="none">Not reviewed</option>
          <option value="investigate">Worth investigating</option>
          <option value="routine">Routine</option>
          <option value="uncertain">Uncertain</option>
        </select>
        <select className={select} value={params.get("demo") || ""} onChange={(e) => set("demo", e.target.value)} aria-label="Demo traffic">
          <option value="">Include demo traffic</option>
          <option value="exclude">Exclude demo traffic</option>
          <option value="only">Demo traffic only</option>
        </select>
        <select className={select} value={params.get("sort") || "recent"} onChange={(e) => set("sort", e.target.value === "recent" ? "" : e.target.value)} aria-label="Sort">
          <option value="recent">Newest first</option>
          <option value="severity">Highest severity</option>
          <option value="anomaly">Most unusual</option>
        </select>
      </div>

      {error && (
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="flex-1"><ErrorBanner message={`Couldn't load sessions: ${error}`} /></div>
          <button className="btn-ghost" onClick={reload}>Try again</button>
        </div>
      )}

      <div className={`glass overflow-hidden transition-opacity ${loading && data ? "opacity-70" : ""}`}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[960px] text-sm">
            <thead>
              <tr className="border-b border-ink/5 text-left text-xs text-ink-faint">
                <th className="px-4 py-3 font-medium">Started</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Outcome</th>
                <th className="whitespace-nowrap px-4 py-3 text-right font-medium">Logins failed / ok</th>
                <th className="px-4 py-3 text-right font-medium">Commands</th>
                <th className="px-4 py-3 text-right font-medium">Duration</th>
                <th className="px-4 py-3 font-medium">Rule severity</th>
                <th className="px-4 py-3 font-medium">
                  <span className="cursor-help border-b border-dotted border-ink-faint" title="Unusualness (0–100): how unusual this session's behaviour is compared with the model's baseline of earlier sessions from the same source. It is not a maliciousness score; a scanner that leaves before login can rank high simply because it is rare.">Unusualness</span>
                </th>
                <th className="px-4 py-3 font-medium">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {loading && !data && !error && (
                <tr><td colSpan={9} className="px-4 py-6 text-center text-sm text-ink-soft" aria-busy="true">
                  <Skeleton className="mb-2 h-8" /><Skeleton className="mb-2 h-8" />Loading SSH sessions…
                </td></tr>
              )}
              {data?.items.map((s) => (
                <tr key={s.id} tabIndex={0} onClick={() => navigate(`/sessions/${s.id}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/sessions/${s.id}`)}
                    className="cursor-pointer border-b border-ink/5 transition last:border-0 hover:bg-white/70 focus:bg-white/80 focus:outline-none">
                  <td className="whitespace-nowrap px-4 py-3">
                    {fmtTime(s.start_ts)}
                    {s.status === "open" && <span className="ml-2 rounded-md bg-sev-low/10 px-1.5 py-0.5 text-[0.68rem] font-semibold text-sev-low">live</span>}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3"><span className="mono">{s.src_ip}</span> {s.is_demo && <DemoTag />}</td>
                  <td className="px-4 py-3"><OutcomePill outcome={s.outcome} /></td>
                  <td className="px-4 py-3 text-right tabular-nums">{s.login_failed} / {s.login_success}</td>
                  <td className="px-4 py-3 text-right tabular-nums">{s.command_count}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-right tabular-nums">{fmtDuration(s.duration)}</td>
                  <td className="px-4 py-3">{s.alert_count > 0 ? <span className="flex items-center gap-2"><SeverityBadge severity={s.severity} /><span className="text-xs text-ink-faint">{s.alert_count}</span></span> : <span className="text-xs text-ink-faint">None</span>}</td>
                  <td className="px-4 py-3"><ScoreBar pct={s.anomaly_pct} /></td>
                  <td className="px-4 py-3"><VerdictTag verdict={s.verdict} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data && data.items.length === 0 && (
          params.toString().replace(/(^|&)(sort|page)=[^&]*/g, "") === ""
            ? <EmptyState title="No SSH sessions in this data source yet">Connect to the decoy, or import a Cowrie dataset and choose it as the data source.</EmptyState>
            : <EmptyState title="No sessions match these filters">Clear a filter or widen the search.</EmptyState>
        )}
        {data && data.total > PAGE && (
          <div className="flex items-center justify-between border-t border-ink/5 px-4 py-3 text-sm">
            <span className="text-ink-soft">{page * PAGE + 1}–{Math.min((page + 1) * PAGE, data.total)} of {data.total}</span>
            <div className="flex gap-2">
              <button className="btn-ghost py-1.5" disabled={page === 0} onClick={() => set("page", String(page - 1))}>Previous</button>
              <button className="btn-ghost py-1.5" disabled={(page + 1) * PAGE >= data.total} onClick={() => set("page", String(page + 1))}>Next</button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
