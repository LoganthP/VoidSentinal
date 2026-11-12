import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, DemoTag, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Skeleton } from "../components/ui";
import { usePoll } from "../lib/api";
import { fmtAgo, fmtTime, OUTCOME, SEVERITY } from "../lib/format";
import type { Alert, Outcome, SensorHealth, Severity } from "../lib/types";
import { useState } from "react";
import { useScope } from "../lib/scope";

interface OverviewData {
  window_hours: number | null;
  window: { from: number; to: number };
  dataset: { id: number; name: string; filename: string; created_at: number; accepted_rows: number; rejected_rows: number; duplicate_rows: number; events: number; first_ts: number; last_ts: number } | null;
  sessions: Record<string, number>;
  events: { failed: number; success: number; commands: number };
  open_alerts: Partial<Record<Severity, number>>;
  series: { bucket_seconds: number; points: { t: number; connections: number; failed_logins: number; commands: number }[] };
  top_sources: { src_ip: string; sessions: number; failed_logins: number; commands: number; max_severity: number; is_demo: number }[];
  top_usernames: { username: string; attempts: number; accepted: number }[];
  top_commands: { command: string; count: number }[];
  recent_alerts: Alert[];
  sensors: SensorHealth[];
  worker: { last_pass_ts?: number; source?: string; last_error?: string | null } | null;
  ml: { active_version: string | null };
}

const WINDOWS = [{ h: 24, label: "24 hours" }, { h: 168, label: "7 days" }, { h: 720, label: "30 days" }];
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEV_NAME = ["none", "low", "medium", "high", "critical"] as const;

const grid = { hidden: {}, show: { transition: { staggerChildren: 0.06 } } };
const tile = { hidden: { opacity: 0, y: 14, scale: 0.98 }, show: { opacity: 1, y: 0, scale: 1, transition: { type: "spring", stiffness: 260, damping: 26 } } };

function Kpi({ label, value, note }: { label: string; value: number | string; note?: string }) {
  return (
    <div className="glass lift p-4">
      <div className="text-sm text-ink-soft">{label}</div>
      <div className="mt-1 font-display text-3xl font-semibold tabular-nums tracking-[-0.03em]">{value}</div>
      {note && <div className="mt-1 text-xs text-ink-faint">{note}</div>}
    </div>
  );
}

function SensorTile({ s }: { s: SensorHealth }) {
  const tone = { active: "#1F9E8F", quiet: "#2F6BFF", stalled: "#D1366B", unknown: "#8592AA" }[s.state];
  return (
    <div className="rounded-2xl bg-white/70 p-3">
      <div className="flex items-center justify-between">
        <span className="mono font-medium">{s.sensor}</span>
        <span className="flex items-center gap-1.5 text-xs font-semibold capitalize" style={{ color: tone }}>
          <span className="relative flex h-2 w-2">
            {s.state !== "stalled" && <span className="ping-soft absolute h-full w-full rounded-full" style={{ background: tone }} />}
            <span className="relative h-2 w-2 rounded-full" style={{ background: tone }} />
          </span>
          {s.state}
        </span>
      </div>
      <p className="mt-1 text-xs text-ink-soft">{s.note}</p>
      <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
        <div><span className="text-ink-faint">Heartbeat</span><div className="font-semibold">{fmtAgo(s.heartbeat_age_s)}</div></div>
        <div><span className="text-ink-faint">Last attacker event</span><div className="font-semibold">{fmtAgo(s.event_age_s)}</div></div>
      </div>
    </div>
  );
}

export default function Overview() {
  const [hours, setHours] = useState(24);
  const { withScope, isDataset } = useScope();
  const { data, error, loading } = usePoll<OverviewData>(withScope(`/overview?hours=${hours}`), isDataset ? 0 : 10000);
  const title = isDataset ? "What this dataset recorded" : "What reached the decoy";

  const windowPicker = isDataset ? null : (
    <div className="glass flex gap-1 p-1" role="group" aria-label="Time window">
      {WINDOWS.map((w) => (
        <button key={w.h} onClick={() => setHours(w.h)}
          className={`rounded-xl px-3 py-1.5 text-sm font-medium transition ${hours === w.h ? "bg-white text-ink shadow-glass" : "text-ink-soft hover:text-ink"}`}>
          {w.label}
        </button>
      ))}
    </div>
  );

  if (error && !data) return (<><PageHeader title={title} action={windowPicker} /><ErrorBanner message={error} /></>);
  if (loading && !data) return (
    <><PageHeader title={title} action={windowPicker} />
      <div className="grid grid-cols-12 gap-4">{[...Array(6)].map((_, i) => <Skeleton key={i} className="col-span-12 h-40 md:col-span-6 xl:col-span-4" />)}</div></>
  );
  if (!data) return null;

  const s = data.sessions;
  const outcomes = (["interactive", "login_no_commands", "auth_failed", "no_auth"] as Outcome[])
    .map((o) => ({ key: o, name: OUTCOME[o].label, value: s[o] || 0, color: OUTCOME[o].color }))
    .filter((o) => o.value > 0);
  const totalOpen = SEV_ORDER.reduce((a, k) => a + (data.open_alerts[k] || 0), 0);
  const points = data.series.points.map((p) => ({
    ...p,
    label: new Date(p.t * 1000).toLocaleString(undefined,
      data.series.bucket_seconds >= 86400 ? { month: "short", day: "numeric" }
        : data.series.bucket_seconds < 60 ? { hour: "2-digit", minute: "2-digit", second: "2-digit" }
        : { hour: "2-digit", minute: "2-digit" }),
  }));
  const noData = s.total === 0;

  return (
    <>
      <PageHeader title={title}
        subtitle={data.dataset
          ? `Every session in the imported file, ${fmtTime(data.window.from)} to ${fmtTime(data.window.to)}.`
          : `SSH activity on your sensors in the last ${WINDOWS.find((w) => w.h === hours)?.label}. Updates every 10 seconds.`}
        action={windowPicker} />

      {noData && !data.dataset && (
        <div className="glass mb-4 p-5 text-sm">
          <p className="font-display font-semibold">No sessions in this window yet</p>
          <p className="mt-1 text-ink-soft">
            In the lab, connect to the decoy with <span className="mono">ssh -p 2222 root@127.0.0.1</span> (any password except <span className="mono">root</span> or <span className="mono">123456</span>), then type a few commands and exit. The session appears here within seconds.
          </p>
        </div>
      )}

      <motion.div variants={grid} initial="hidden" animate="show" className="grid grid-cols-12 gap-4">
        <motion.div variants={tile} className="col-span-6 md:col-span-3"><Kpi label="Sessions" value={s.total} note={`${s.sources} distinct sources`} /></motion.div>
        <motion.div variants={tile} className="col-span-6 md:col-span-3"><Kpi label="Reached the shell" value={s.interactive} note={`${data.events.commands} commands typed`} /></motion.div>
        <motion.div variants={tile} className="col-span-6 md:col-span-3"><Kpi label="Failed logins" value={data.events.failed} note={`${data.events.success} accepted by the decoy`} /></motion.div>
        <motion.div variants={tile} className="col-span-6 md:col-span-3"><Kpi label="Open alerts" value={totalOpen} note={data.dataset ? "Imported data · no demo traffic" : s.demo ? `${s.demo} demo sessions in window` : "No demo traffic in window"} /></motion.div>

        <motion.div variants={tile} className="col-span-12 xl:col-span-8">
          <Card title="Activity" className="h-full" action={
            <div className="flex gap-4 text-xs text-ink-soft">
              <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-phase-connect" />Connections</span>
              <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-phase-auth" />Failed logins</span>
              <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-phase-shell" />Commands</span>
            </div>}>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={points} margin={{ left: -18, right: 6, top: 6 }}>
                  <defs>
                    {[["c", "#5B8DEF"], ["f", "#9B6BF2"], ["m", "#E0631A"]].map(([id, c]) => (
                      <linearGradient key={id} id={`g-${id}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={c} stopOpacity={0.35} /><stop offset="100%" stopColor={c} stopOpacity={0.02} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid stroke="#14223B" strokeOpacity={0.06} vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#5F6B84" }} tickLine={false} axisLine={false} minTickGap={28} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#5F6B84" }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ borderRadius: 14, border: "1px solid rgba(255,255,255,.9)", background: "rgba(255,255,255,.92)", boxShadow: "0 12px 28px -12px rgba(40,72,140,.3)", fontSize: 12 }} />
                  <Area type="monotone" dataKey="connections" name="Connections" stroke="#5B8DEF" strokeWidth={2} fill="url(#g-c)" />
                  <Area type="monotone" dataKey="failed_logins" name="Failed logins" stroke="#9B6BF2" strokeWidth={2} fill="url(#g-f)" />
                  <Area type="monotone" dataKey="commands" name="Commands" stroke="#E0631A" strokeWidth={2} fill="url(#g-m)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>

        <motion.div variants={tile} className="col-span-12 md:col-span-6 xl:col-span-4">
          {data.dataset ? (
          <Card title="Where this evidence came from" className="h-full" action={<Link to="/import" className="text-xs font-semibold text-signal">Datasets</Link>}>
            <dl className="grid grid-cols-2 gap-3 text-sm">
              <div className="col-span-2"><dt className="text-xs text-ink-faint">File</dt><dd className="mono truncate">{data.dataset.filename}</dd></div>
              <div><dt className="text-xs text-ink-faint">Imported</dt><dd className="font-medium">{fmtTime(data.dataset.created_at)}</dd></div>
              <div><dt className="text-xs text-ink-faint">Events stored</dt><dd className="font-medium tabular-nums">{data.dataset.events.toLocaleString()}</dd></div>
              <div><dt className="text-xs text-ink-faint">Rows rejected</dt><dd className="font-medium tabular-nums">{data.dataset.rejected_rows.toLocaleString()}</dd></div>
              <div><dt className="text-xs text-ink-faint">Duplicates skipped</dt><dd className="font-medium tabular-nums">{data.dataset.duplicate_rows.toLocaleString()}</dd></div>
            </dl>
            <p className="mt-3 text-xs text-ink-faint">Historical Cowrie log, analyzed with the same rules and features as live traffic. Its anomaly model is trained on this dataset only. Passwords were stripped at import.</p>
          </Card>
          ) : (
          <Card title="Sensor health" className="h-full" action={<Link to="/sensors" className="text-xs font-semibold text-signal">Details</Link>}>
            <div className="flex flex-col gap-3">
              {data.sensors.length === 0
                ? <EmptyState title="No sensor has reported yet">Start the collector; its heartbeat appears within a minute.</EmptyState>
                : data.sensors.map((x) => <SensorTile key={x.sensor} s={x} />)}
              <p className="text-xs text-ink-faint">
                Worker last ran {data.worker?.last_pass_ts ? fmtAgo(Date.now() / 1000 - data.worker.last_pass_ts) : "—"} · source: {data.worker?.source ?? "—"}
                {data.worker?.last_error && <span className="block text-sev-critical">Last read error: {data.worker.last_error}</span>}
              </p>
            </div>
          </Card>
          )}
        </motion.div>

        <motion.div variants={tile} className="col-span-12 md:col-span-6 xl:col-span-4">
          <Card title="How sessions ended" className="h-full">
            {outcomes.length === 0 ? <EmptyState title="Nothing to break down yet" /> : (
              <div className="flex items-center gap-4">
                <div className="h-40 w-40 shrink-0">
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={outcomes} dataKey="value" nameKey="name" innerRadius={44} outerRadius={70} paddingAngle={3} stroke="none">
                        {outcomes.map((o) => <Cell key={o.key} fill={o.color} />)}
                      </Pie>
                      <Tooltip contentStyle={{ borderRadius: 12, fontSize: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <ul className="flex flex-1 flex-col gap-2 text-sm">
                  {outcomes.map((o) => (
                    <li key={o.key} className="flex items-center justify-between gap-2">
                      <Link to={`/sessions?outcome=${o.key}`} className="flex items-center gap-2 hover:text-signal">
                        <span className="h-2.5 w-2.5 rounded-[4px]" style={{ background: o.color }} />{o.name}
                      </Link>
                      <span className="font-semibold tabular-nums">{o.value}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>
        </motion.div>

        <motion.div variants={tile} className="col-span-12 md:col-span-6 xl:col-span-4">
          <Card title="Open alerts by severity" className="h-full" action={<Link to="/alerts" className="text-xs font-semibold text-signal">Open queue</Link>}>
            <div className="flex flex-col gap-2.5">
              {SEV_ORDER.map((k) => {
                const n = data.open_alerts[k] || 0;
                return (
                  <Link key={k} to={`/alerts?severity=${k}`} className="group flex items-center gap-3">
                    <span className="w-16 text-sm font-medium" style={{ color: SEVERITY[k].color }}>{SEVERITY[k].label}</span>
                    <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-ink/5">
                      <div className="h-full rounded-full transition-all" style={{ width: `${totalOpen ? (n / totalOpen) * 100 : 0}%`, background: SEVERITY[k].color }} />
                    </div>
                    <span className="w-8 text-right text-sm font-semibold tabular-nums">{n}</span>
                  </Link>
                );
              })}
            </div>
          </Card>
        </motion.div>

        <motion.div variants={tile} className="col-span-12 md:col-span-6 xl:col-span-4">
          <Card title="Busiest sources" className="h-full">
            {data.top_sources.length === 0 ? <EmptyState title="No sources yet" /> : (
              <ul className="flex flex-col divide-y divide-ink/5 text-sm">
                {data.top_sources.map((t) => (
                  <li key={t.src_ip} className="flex items-center justify-between gap-2 py-2">
                    <Link to={`/sessions?q=${encodeURIComponent(t.src_ip)}`} className="mono flex items-center gap-2 hover:text-signal">
                      {t.src_ip} {t.is_demo ? <DemoTag /> : null}
                    </Link>
                    <span className="flex items-center gap-3 text-xs text-ink-soft">
                      {t.sessions} sess · {t.failed_logins} fails
                      {t.max_severity > 0 && <SeverityBadge severity={SEV_NAME[t.max_severity]} />}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </motion.div>

        <motion.div variants={tile} className="col-span-12 xl:col-span-6">
          <Card title="Newest open alerts" className="h-full">
            {data.recent_alerts.length === 0 ? <EmptyState title="No open alerts">Rule findings appear here as soon as matching events arrive.</EmptyState> : (
              <ul className="flex flex-col gap-2">
                {data.recent_alerts.map((a) => (
                  <li key={a.id}>
                    <Link to={a.session_id ? `/sessions/${a.session_id}?alert=${a.id}` : "/alerts"} className="flex items-start gap-3 rounded-2xl bg-white/60 p-3 transition hover:bg-white">
                      <SeverityBadge severity={a.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-semibold">{a.title}</div>
                        <div className="truncate text-xs text-ink-soft">{a.reason}</div>
                      </div>
                      <span className="shrink-0 text-xs text-ink-faint">{fmtTime(a.last_ts)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </motion.div>

        <motion.div variants={tile} className="col-span-12 md:col-span-6 xl:col-span-3">
          <Card title="Usernames tried" className="h-full">
            {data.top_usernames.length === 0 ? <EmptyState title="No login attempts yet" /> : (
              <ul className="flex flex-col gap-1.5 text-sm">
                {data.top_usernames.map((u) => (
                  <li key={u.username} className="flex justify-between gap-2">
                    <span className="mono truncate">{u.username}</span>
                    <span className="tabular-nums text-ink-soft">{u.attempts}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </motion.div>

        <motion.div variants={tile} className="col-span-12 md:col-span-6 xl:col-span-3">
          <Card title="Most typed commands" className="h-full">
            {data.top_commands.length === 0 ? <EmptyState title="No commands yet" /> : (
              <ul className="flex flex-col gap-1.5 text-sm">
                {data.top_commands.map((c) => (
                  <li key={c.command} className="flex justify-between gap-2">
                    <Link to={`/sessions?q=${encodeURIComponent(c.command)}`} className="mono truncate hover:text-signal" title={c.command}>{c.command}</Link>
                    <span className="tabular-nums text-ink-soft">{c.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </motion.div>
      </motion.div>
    </>
  );
}
