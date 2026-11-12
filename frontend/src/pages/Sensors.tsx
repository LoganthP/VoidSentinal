import { Card, EmptyState, ErrorBanner, PageHeader, Skeleton } from "../components/ui";
import { usePoll } from "../lib/api";
import { fmtAgo, fmtTime } from "../lib/format";
import type { SensorHealth } from "../lib/types";

interface SensorsResp {
  sensors: SensorHealth[];
  worker: { last_pass_ts?: number; last_new?: number; source?: string; path?: string; log_group?: string; region?: string;
            checkpoint?: unknown; checkpoint_ms?: number | null; last_error?: string | null } | null;
  worker_state: "running" | "stalled" | "unknown";
}
interface Meta {
  rules: { id: string; title: string; severity: string; trigger: string; attack: string | null }[];
  categories: Record<string, string>; source: string; log_group: string | null; demo_cidrs: string[]; ml_include_demo: boolean;
}

const TONE = { active: "#1F9E8F", quiet: "#2F6BFF", stalled: "#D1366B", unknown: "#8592AA", running: "#1F9E8F" } as const;

export default function Sensors() {
  const { data, error, loading } = usePoll<SensorsResp>("/sensors", 10000);
  const { data: meta } = usePoll<Meta>("/meta");
  const now = Date.now() / 1000;

  return (
    <>
      <PageHeader title="Sensors & rules" subtitle="Is collection working, and what does each detection rule look for." />
      {error && <div className="mb-4"><ErrorBanner message={error} /></div>}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 lg:col-span-7">
          <Card title="Decoy sensors">
            {loading && !data ? <Skeleton className="h-32" /> : !data?.sensors.length ? (
              <EmptyState title="No sensor has reported yet">
                The collector sends a heartbeat every minute. In the lab, run <span className="mono">docker compose --profile lab up -d</span>; in the cloud check <span className="mono">systemctl status voidsentinel-collector</span> on the sensor via Session Manager.
              </EmptyState>
            ) : (
              <div className="grid gap-3 md:grid-cols-2">
                {data.sensors.map((s) => (
                  <div key={s.sensor} className="rounded-2xl bg-white/70 p-4">
                    <div className="flex items-center justify-between">
                      <span className="mono font-semibold">{s.sensor}</span>
                      <span className="text-xs font-semibold capitalize" style={{ color: TONE[s.state] }}>{s.state}</span>
                    </div>
                    <p className="mt-1 text-xs text-ink-soft">{s.note}</p>
                    <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
                      <div><dt className="text-ink-faint">Collector heartbeat</dt><dd className="font-semibold">{fmtAgo(s.heartbeat_age_s)}</dd></div>
                      <div><dt className="text-ink-faint">Last attacker event</dt><dd className="font-semibold">{fmtAgo(s.event_age_s)}</dd></div>
                      <div><dt className="text-ink-faint">Events shipped</dt><dd className="font-semibold tabular-nums">{s.shipped_total ?? "—"}</dd></div>
                      <div><dt className="text-ink-faint">Cowrie log last written</dt><dd className="font-semibold">{fmtAgo(s.cowrie_log_age_s)}</dd></div>
                      <div><dt className="text-ink-faint">First seen</dt><dd className="font-semibold">{fmtTime(s.first_seen)}</dd></div>
                      <div><dt className="text-ink-faint">Collector</dt><dd className="font-semibold">v{s.collector_version ?? "?"}</dd></div>
                    </dl>
                  </div>
                ))}
              </div>
            )}
            <p className="mt-3 text-xs text-ink-faint">
              Quiet means the heartbeat is fresh but no one has connected for an hour — normal. Stalled means no heartbeat for over 3 minutes — the collector, network path or CloudWatch delivery needs checking.
            </p>
          </Card>
        </div>

        <div className="col-span-12 lg:col-span-5">
          <Card title="Ingestion worker">
            {data?.worker ? (
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <div><dt className="text-xs text-ink-faint">State</dt><dd className="font-semibold capitalize" style={{ color: TONE[data.worker_state] }}>{data.worker_state}</dd></div>
                <div><dt className="text-xs text-ink-faint">Last pass</dt><dd className="font-semibold">{data.worker.last_pass_ts ? fmtAgo(now - data.worker.last_pass_ts) : "—"}</dd></div>
                <div><dt className="text-xs text-ink-faint">Source</dt><dd className="font-semibold">{data.worker.source === "cloudwatch" ? "CloudWatch Logs" : "Local file (lab)"}</dd></div>
                <div className="min-w-0"><dt className="text-xs text-ink-faint">{data.worker.source === "cloudwatch" ? "Log group" : "File"}</dt>
                  <dd className="mono truncate" title={data.worker.log_group || data.worker.path}>{data.worker.log_group || data.worker.path}</dd></div>
                {data.worker.checkpoint_ms != null && <div className="col-span-2"><dt className="text-xs text-ink-faint">CloudWatch checkpoint</dt><dd>{fmtTime(data.worker.checkpoint_ms / 1000)} (re-reads a 10-minute overlap; duplicates are ignored)</dd></div>}
                {data.worker.last_error && <div className="col-span-2 rounded-xl bg-sev-critical/10 p-2 text-xs text-sev-critical">{data.worker.last_error}</div>}
              </dl>
            ) : <EmptyState title="The worker hasn't run yet">Start it with <span className="mono">docker compose up -d worker</span>.</EmptyState>}
            {meta && (
              <p className="mt-3 text-xs text-ink-faint">
                Demo source ranges: {meta.demo_cidrs.length ? <span className="mono">{meta.demo_cidrs.join(", ")}</span> : "none configured"}. Sessions from these are tagged demo and excluded from the evaluation.
              </p>
            )}
          </Card>
        </div>

        <div className="col-span-12">
          <Card title="Detection rules">
            {!meta ? <Skeleton className="h-40" /> : (
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {meta.rules.map((r) => (
                  <div key={r.id} className="rounded-2xl bg-white/60 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold">{r.title}</span>
                      <span className="text-xs capitalize text-ink-soft">{r.severity}</span>
                    </div>
                    <p className="mt-1 text-xs text-ink-soft">Triggers when {r.trigger}.</p>
                    {r.attack && <p className="mt-1 text-xs text-ink-faint">MITRE ATT&CK: {r.attack}</p>}
                    <p className="mono mt-1.5 text-[0.7rem] text-ink-faint">{r.id}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
