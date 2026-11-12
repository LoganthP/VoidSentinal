import { Eye } from "lucide-react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { DemoTag, EmptyState, ErrorBanner, OutcomePill, PageHeader, ScoreBar, SeverityBadge, Skeleton, VerdictTag } from "../components/ui";
import { usePoll } from "../lib/api";
import { fmtTime, SEVERITY } from "../lib/format";
import { useScope } from "../lib/scope";
import type { Alert } from "../lib/types";

const TABS = [
  { key: "open", label: "Needs review" },
  { key: "triaged", label: "Triaged" },
  { key: "all", label: "All" },
];
export interface RuleMeta { id: string; title: string; severity: string; trigger: string; attack: string | null }

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const status = params.get("status") || "open";
  const severity = params.get("severity") || "";
  const ruleId = params.get("rule_id") || "";
  const { withScope, isDataset } = useScope();
  const q = new URLSearchParams({ status, limit: "200" });
  if (severity) q.set("severity", severity);
  if (ruleId) q.set("rule_id", ruleId);
  const { data, error, loading } = usePoll<{ total: number; items: Alert[]; counts: Record<string, number> }>(withScope(`/alerts?${q}`), isDataset ? 0 : 10000);
  const { data: meta } = usePoll<{ rules: RuleMeta[] }>("/meta");
  const rule = (id: string) => meta?.rules.find((r) => r.id === id);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHeader title="Alert queue"
        subtitle="Rule findings, most severe first. View evidence opens the SSH session with the triggering events highlighted; saving a verdict there moves its alerts to Triaged." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="glass flex gap-1 p-1" role="tablist">
          {TABS.map((t) => (
            <button key={t.key} role="tab" aria-selected={status === t.key} onClick={() => set("status", t.key === "open" ? "" : t.key)}
              className={`rounded-xl px-3 py-1.5 text-sm font-medium transition ${status === t.key ? "bg-white shadow-glass" : "text-ink-soft hover:text-ink"}`}>
              {t.label}
              {t.key !== "all" && <span className="ml-1.5 text-xs text-ink-faint">{data?.counts[t.key] ?? 0}</span>}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {["", "critical", "high", "medium", "low"].map((s) => (
            <button key={s || "any"} onClick={() => set("severity", s)}
              className={`rounded-full px-3 py-1 text-xs font-semibold transition ${severity === s ? "bg-white shadow-glass" : "bg-white/40 text-ink-soft hover:bg-white/70"}`}
              style={s && severity === s ? { color: SEVERITY[s as keyof typeof SEVERITY].color } : undefined}>
              {s ? SEVERITY[s as keyof typeof SEVERITY].label : "Any severity"}
            </button>
          ))}
        </div>
        {ruleId && (
          <button onClick={() => set("rule_id", "")} className="rounded-full bg-signal-soft px-3 py-1 text-xs font-semibold text-signal" title="Clear rule filter">
            {rule(ruleId)?.title ?? ruleId} ✕
          </button>
        )}
      </div>

      {error && <div className="mb-4"><ErrorBanner message={`Couldn't load alerts: ${error}`} /></div>}
      {loading && !data && <div className="flex flex-col gap-3" aria-busy="true">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-28" />)}</div>}

      {data && data.items.length === 0 && (
        <div className="glass">
          <EmptyState title={status === "open" ? "Nothing waiting for review" : status === "triaged" ? "No triaged alerts yet" : "No alerts here"}>
            {status === "open" ? "New findings appear automatically. Quiet periods are normal; check Sensors & rules if you expect traffic."
              : status === "triaged" ? "Open an alert, save a verdict on its session, and it moves here." : "Try another tab or severity."}
          </EmptyState>
        </div>
      )}

      <ul className="flex flex-col gap-3">
        {data?.items.map((a) => {
          const r = rule(a.rule_id);
          const go = () => a.session_id && navigate(`/sessions/${a.session_id}?alert=${a.id}`);
          return (
            <li key={a.id} className="glass lift flex flex-col gap-3 p-4 md:flex-row md:items-center">
              <div className="w-1 self-stretch rounded-full max-md:hidden" style={{ background: SEVERITY[a.severity].color }} aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="font-display font-semibold">{a.title}</span>
                  {a.is_demo && <DemoTag />}
                  {a.status === "triaged" && <span className="rounded-md bg-sev-low/10 px-1.5 py-0.5 text-[0.68rem] font-semibold text-sev-low">Triaged</span>}
                </div>
                <p className="mt-1 text-sm">{a.reason}</p>
                {r && <p className="mt-1 text-xs text-ink-soft">Triggers when {r.trigger}.{r.attack && <> ATT&CK: {r.attack}.</>}</p>}
                <p className="mt-1.5 text-xs text-ink-faint">
                  <span className="mono">{a.src_ip}</span> · {fmtTime(a.first_ts)}{a.last_ts - a.first_ts > 1 && <> → {fmtTime(a.last_ts)}</>}
                  {a.related_sessions.length > 1 && <> · spans {a.related_sessions.length}{a.related_sessions.length >= 50 ? "+" : ""} connections</>}
                </p>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-4 md:flex-col md:items-end md:gap-2">
                <button className="btn-primary py-1.5" onClick={go} disabled={!a.session_id}>
                  <Eye className="h-4 w-4" />View {a.evidence_count} evidence event{a.evidence_count === 1 ? "" : "s"}
                </button>
                <div className="flex items-center gap-3">
                  {a.outcome && <OutcomePill outcome={a.outcome} />}
                  <ScoreBar pct={a.anomaly_pct} />
                </div>
                <VerdictTag verdict={a.verdict} />
              </div>
            </li>
          );
        })}
      </ul>
    </>
  );
}
