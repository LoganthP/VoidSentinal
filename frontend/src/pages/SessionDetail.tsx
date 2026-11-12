import { motion } from "framer-motion";
import { ArrowLeft, Check, Database, EyeOff, RadioTower } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import type { RuleMeta } from "./Alerts";
import { Card, DemoTag, EmptyState, ErrorBanner, OutcomePill, ScoreBar, SeverityBadge, Skeleton } from "../components/ui";
import { api, usePoll } from "../lib/api";
import { fmtClock, fmtDuration, fmtTime, VERDICT } from "../lib/format";
import type { Alert, Session, TimelineEvent, Verdict } from "../lib/types";

interface Detail {
  session: Session;
  events: TimelineEvent[];
  alerts: Alert[];
  source_context: { sessions_from_source: number; first_seen: number };
  events_truncated?: number;
  provenance: { kind: "live"; sensor: string } | { kind: "dataset"; id: number; name: string; filename: string; created_at: number };
  category_labels: Record<string, string>;
}

const fmtNum = (v: number) => (Number.isInteger(v) ? String(v) : v.toFixed(v < 10 ? 2 : 1));

const PHASE_STYLE: Record<string, { color: string; label: string }> = {
  connect: { color: "#5B8DEF", label: "Connect" },
  auth: { color: "#9B6BF2", label: "Login" },
  shell: { color: "#E0631A", label: "Shell" },
  close: { color: "#8592AA", label: "Close" },
  other: { color: "#8592AA", label: "Other" },
};

function Timeline({ events, highlight, onPick }: { events: TimelineEvent[]; highlight: Set<string>; onPick: (ids: number[]) => void }) {
  const firstHit = useRef<HTMLLIElement | null>(null);
  useEffect(() => {
    if (highlight.size && firstHit.current) firstHit.current.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [highlight]);

  let marked = false;
  return (
    <ol className="relative">
      {/* the trace */}
      <div className="absolute bottom-3 left-[5.6rem] top-3 w-[2px] rounded-full bg-gradient-to-b from-phase-connect/40 via-phase-auth/40 to-phase-shell/40" aria-hidden />
      {events.map((e, i) => {
        const p = PHASE_STYLE[e.phase] ?? PHASE_STYLE.other;
        const hit = highlight.has(e.uid);
        const isCmd = e.eventid === "cowrie.command.input" || e.eventid === "cowrie.command.failed";
        const prevPhase = i > 0 ? events[i - 1].phase : null;
        const ref = hit && !marked ? (marked = true, firstHit) : undefined;
        return (
          <li key={e.uid} ref={ref} className="relative">
            {prevPhase !== e.phase && (
              <div className="ml-[7rem] mt-3 pb-1 text-xs font-semibold" style={{ color: p.color }}>{p.label}</div>
            )}
            <div className={`flex items-start gap-3 rounded-2xl py-1.5 pr-2 transition ${hit ? "bg-white shadow-glass" : ""}`}>
              <span className="w-[4.6rem] shrink-0 pt-0.5 text-right text-xs tabular-nums text-ink-faint" title={fmtTime(e.ts)}>
                +{e.offset_s < 10 ? e.offset_s.toFixed(2) : e.offset_s.toFixed(1)}s
              </span>
              <span className="relative mt-1 flex h-3.5 w-3.5 shrink-0 items-center justify-center">
                {hit && <span className="ping-soft absolute h-full w-full rounded-full" style={{ background: p.color }} />}
                <span className="relative h-3 w-3 rounded-full border-2 border-white" style={{ background: p.color, boxShadow: `0 0 0 3px ${p.color}22` }} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-semibold">{e.title}</span>
                  {e.redacted && <span className="inline-flex items-center gap-1 rounded-md bg-ink/5 px-1.5 text-[0.68rem] text-ink-soft"><EyeOff className="h-3 w-3" />redacted</span>}
                  {e.alert_ids.length > 0 && (
                    <button onClick={() => onPick(e.alert_ids)} className="rounded-md bg-sev-high/10 px-1.5 text-[0.68rem] font-semibold text-sev-high hover:bg-sev-high/20">
                      evidence for {e.alert_ids.length} alert{e.alert_ids.length > 1 ? "s" : ""}
                    </button>
                  )}
                </div>
                {e.detail && (
                  isCmd
                    ? <pre className="mono mt-1 whitespace-pre-wrap break-all rounded-xl bg-[#F3F7FD] px-3 py-1.5 text-ink">{e.detail}</pre>
                    : <div className="mt-0.5 break-all text-xs text-ink-soft">{e.detail}</div>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function VerdictPanel({ session, onSaved }: { session: Session & { verdict_by?: string | null; alerts_updated?: number }; onSaved: (s: Session) => void }) {
  const [choice, setChoice] = useState<Verdict>(session.verdict);
  const [note, setNote] = useState(session.verdict_note || "");
  const [state, setState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [err, setErr] = useState("");
  const [moved, setMoved] = useState<number | null>(null);
  useEffect(() => { setChoice(session.verdict); setNote(session.verdict_note || ""); }, [session.id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function save(v: Verdict) {
    setState("saving");
    try {
      const s = await api<Session & { alerts_updated: number }>(`/sessions/${session.id}/verdict`, { method: "POST", body: JSON.stringify({ verdict: v, note: note || null }) });
      onSaved(s); setChoice(v); setState("saved"); setMoved(v ? s.alerts_updated : null);
    } catch (e) { setErr((e as Error).message); setState("error"); }
  }

  return (
    <Card title="Your verdict" className="ring-2 ring-signal/15">
      <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Verdict">
        {(Object.keys(VERDICT) as Exclude<Verdict, null>[]).map((v) => (
          <button key={v} role="radio" aria-checked={choice === v} data-on={choice === v} onClick={() => setChoice(v)}
                  className="soft-btn px-2 text-xs" style={choice === v ? { color: VERDICT[v].color } : undefined}>
            {VERDICT[v].label}
          </button>
        ))}
      </div>
      <textarea className="field mt-3 h-20 w-full resize-none" placeholder="Note for later (optional): what you checked, why"
                value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} aria-label="Verdict note" />
      <div className="mt-3 flex items-center gap-2">
        <button className="btn-primary flex-1" disabled={!choice || state === "saving"} onClick={() => save(choice)}>
          {state === "saved" ? <><Check className="h-4 w-4" />Verdict saved</> : state === "saving" ? "Saving…" : "Save verdict"}
        </button>
        {session.verdict && <button className="btn-ghost" onClick={() => save(null)}>Clear</button>}
      </div>
      {state === "error" && <p className="mt-2 text-sm text-sev-critical">{err}</p>}
      {state === "saved" && moved != null && (
        <p role="status" className="mt-3 rounded-xl bg-sev-low/10 p-2.5 text-sm">
          Verdict saved. {moved > 0 ? <>{moved} alert{moved === 1 ? "" : "s"} moved to <Link className="font-semibold text-signal" to="/alerts?status=triaged">Triaged</Link>.</> : "This session had no alerts."}
        </p>
      )}
      {session.verdict && session.verdict_by && state !== "saved" && (
        <p className="mt-2 text-xs text-ink-soft">Recorded by <b>{session.verdict_by}</b>{session.verdict_at ? ` on ${fmtTime(session.verdict_at)}` : ""}.</p>
      )}
      <p className="mt-2 text-xs text-ink-faint">Saving marks this session's alerts as triaged. Verdicts feed the ML evaluation.</p>
    </Card>
  );
}

export default function SessionDetail() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const { data, error, loading, setData } = usePoll<Detail>(`/sessions/${id}`, 0);
  const { data: meta } = usePoll<{ rules: RuleMeta[] }>("/meta");
  const selected = Number(params.get("alert") || 0) || null;

  const highlight = useMemo(() => {
    const a = data?.alerts.find((x) => x.id === selected);
    return new Set(a?.evidence || []);
  }, [data, selected]);

  const pick = (alertId: number | null) => {
    const next = new URLSearchParams(params);
    if (alertId && alertId !== selected) next.set("alert", String(alertId)); else next.delete("alert");
    setParams(next, { replace: true });
  };

  if (error && !data) return <ErrorBanner message={error} />;
  if (loading && !data) return <div className="grid gap-4"><Skeleton className="h-32" /><Skeleton className="h-96" /></div>;
  if (!data) return null;
  const s = data.session;
  const relatedOther = (a: Alert) => (a.related_sessions || []).filter((x) => x !== s.id);

  return (
    <>
      <Link to="/sessions" className="mb-4 inline-flex items-center gap-1.5 text-sm font-medium text-ink-soft hover:text-ink">
        <ArrowLeft className="h-4 w-4" />All sessions
      </Link>

      <motion.header initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="glass-strong mb-4 p-5">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="h-title mono !font-mono !text-[1.5rem]">{s.src_ip}</h1>
          <OutcomePill outcome={s.outcome} />
          {s.alert_count > 0 && <SeverityBadge severity={s.severity} />}
          {s.is_demo && <DemoTag />}
          {data.provenance.kind === "dataset"
            ? <span className="inline-flex items-center gap-1.5 rounded-md bg-[#F1EBFF] px-2 py-0.5 text-xs font-semibold text-[#7A4FE0]" title={data.provenance.filename}><Database className="h-3.5 w-3.5" />Imported: {data.provenance.name}</span>
            : <span className="inline-flex items-center gap-1.5 rounded-md bg-sev-low/10 px-2 py-0.5 text-xs font-semibold text-sev-low"><RadioTower className="h-3.5 w-3.5" />Live sensor</span>}
          {s.protocol && <span className="rounded-md bg-white/80 px-2 py-0.5 text-xs font-semibold uppercase text-ink-soft">{s.protocol}</span>}
          {s.status === "open" && <span className="rounded-md bg-sev-low/10 px-2 py-0.5 text-xs font-semibold text-sev-low">Still connected · refreshing</span>}
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-3 xl:grid-cols-6">
          {[
            ["Started", fmtTime(s.start_ts)],
            ["Duration", fmtDuration(s.duration)],
            ["Sensor", s.sensor],
            ["Session ID", s.session],
            ["SSH client", s.client_version || "—"],
            ["From this source", `${data.source_context.sessions_from_source} session${data.source_context.sessions_from_source === 1 ? "" : "s"} since ${fmtClock(data.source_context.first_seen)}`],
          ].map(([k, v]) => (
            <div key={k} className="min-w-0"><dt className="text-xs text-ink-faint">{k}</dt><dd className={`truncate font-medium ${k === "Session ID" || k === "SSH client" ? "mono" : ""}`} title={String(v)}>{v}</dd></div>
          ))}
        </dl>
      </motion.header>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 xl:col-span-7">
          <Card title="What happened" action={<span className="text-xs text-ink-faint">{data.events.length} events · times relative to connect</span>}>
            {data.events.length === 0 ? <EmptyState title="No events stored for this session" /> :
              <Timeline events={data.events} highlight={highlight} onPick={(ids) => pick(ids[0])} />}
            {(data.events_truncated ?? 0) > 0 && (
              <p className="mt-3 rounded-xl bg-white/60 p-2.5 text-xs text-ink-soft">
                Showing the first {data.events.length.toLocaleString()} events. {data.events_truncated!.toLocaleString()} more are stored; the counts and rules above use all of them.
              </p>
            )}
          </Card>
        </div>

        <div className="col-span-12 flex flex-col gap-4 xl:col-span-5">
          <VerdictPanel session={s} onSaved={(ns) => setData({ ...data, session: ns, alerts: data.alerts.map((a) => ({ ...a, status: ns.verdict ? "triaged" : "open" })) })} />

          <Card title="Why it was flagged" action={<span className="text-xs text-ink-faint">Select an alert to light up its evidence</span>}>
            {data.alerts.length === 0 ? <p className="text-sm text-ink-soft">No rule matched this session.</p> : (
              <ul className="flex flex-col gap-2">
                {data.alerts.map((a) => (
                  <li key={a.id}>
                    <button onClick={() => pick(a.id)} aria-pressed={selected === a.id}
                      className={`w-full rounded-2xl p-3 text-left transition ${selected === a.id ? "bg-white shadow-glass ring-2 ring-signal/30" : "bg-white/55 hover:bg-white"}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-semibold">{a.title}</span>
                        <SeverityBadge severity={a.severity} />
                      </div>
                      <p className="mt-1 text-xs text-ink-soft">{a.reason}</p>
                      {meta?.rules.find((r) => r.id === a.rule_id) && (
                        <p className="mt-1 text-[0.72rem] text-ink-faint">Rule threshold: {meta.rules.find((r) => r.id === a.rule_id)!.trigger}.</p>
                      )}
                      <p className="mt-1.5 text-[0.7rem] text-ink-faint">
                        {a.rule_id} · {a.evidence?.length ?? 0} evidence events · {a.status}
                        {relatedOther(a).length > 0 && <> · also in {relatedOther(a).slice(0, 8).map((x, i) => <span key={x}>{i > 0 && ", "}<Link onClick={(e) => e.stopPropagation()} className="text-signal" to={`/sessions/${x}?alert=${a.id}`}>#{x}</Link></span>)}{(a.related_count ?? 0) - 1 > 8 && ` and ${(a.related_count ?? 0) - 1 - 8} more`}</>}
                      </p>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="How unusual it is">
            {s.status !== "closed" ? <p className="text-sm text-ink-soft">Scored once the session closes.</p>
              : s.anomaly_pct == null ? <p className="text-sm text-ink-soft">No baseline model yet. The worker trains one automatically once enough sessions have completed (see Anomaly ranking).</p>
              : (
                <>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-ink-soft">More unusual than {s.anomaly_pct.toFixed(0)}% of baseline sessions</span>
                    <ScoreBar pct={s.anomaly_pct} />
                  </div>
                  <p className="mt-1 text-xs text-ink-faint">This measures unusualness compared with earlier traffic, not maliciousness. It is shown separately from rule severity.</p>
                  {s.explanation && s.explanation.length > 0 && (
                    <ul className="mt-3 flex flex-col gap-2">
                      {s.explanation.map((x) => (
                        <li key={x.feature} className="rounded-xl bg-white/60 p-2.5 text-sm">
                          <div className="flex justify-between gap-2"><span className="font-medium">{x.label}</span><span className="tabular-nums" style={{ color: x.direction === "higher" ? "#D2560F" : "#2F6BFF" }}>{x.direction}</span></div>
                          <div className="text-xs text-ink-soft">
                            {x.feature === "time_to_first_command_s" && s.command_count === 0
                              ? <>No command was ever run, so this counts as the whole session (<b className="tabular-nums">{fmtNum(x.value)}s</b>) · typical: <span className="tabular-nums">{fmtNum(x.baseline_median)}s</span></>
                              : <>This session: <b className="tabular-nums">{fmtNum(x.value)}</b> · typical: <span className="tabular-nums">{fmtNum(x.baseline_median)}</span></>}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="mt-2 text-[0.7rem] text-ink-faint">Model {s.model_version}</p>
                </>
              )}
          </Card>

          <Card title="Session facts">
            <div className="flex flex-col gap-3 text-sm">
              <div>
                <div className="text-xs text-ink-faint">Command categories</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {s.categories.length ? s.categories.map((c) => <span key={c} className="rounded-lg bg-white/80 px-2 py-0.5 text-xs">{data.category_labels[c] || c}</span>) : <span className="text-ink-soft">None</span>}
                </div>
              </div>
              <div>
                <div className="text-xs text-ink-faint">Usernames tried (passwords are never stored)</div>
                <div className="mono mt-1 break-all">{s.usernames.length ? s.usernames.join(", ") : "—"}</div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                {[["Failed logins", s.login_failed], ["Commands", s.command_count], ["Downloads", s.download_count]].map(([k, v]) => (
                  <div key={k} className="rounded-xl bg-white/60 p-2"><div className="font-display text-lg font-semibold tabular-nums">{v}</div><div className="text-[0.7rem] text-ink-faint">{k}</div></div>
                ))}
              </div>
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
