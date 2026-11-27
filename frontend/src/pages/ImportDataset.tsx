import { CheckCircle2, FileJson, Info, ShieldCheck, Trash2, UploadCloud, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, ErrorBanner, PageHeader } from "../components/ui";
import { api, ApiError, API_HEADERS } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtTime } from "../lib/format";
import { useScope, type Dataset } from "../lib/scope";

interface Report {
  filename: string; format: "json" | "csv"; size_bytes: number; total_rows: number; accepted_rows: number; rejected_rows: number;
  csv: { headers: string[]; mapping: Record<string, string>; suggested: Record<string, string>; fields: string[]; required: string[] } | null;
  prefixed_eventids: number;
  rejections: { reason: string; label: string; count: number; samples: { file: string; line: number; text: string }[] }[];
  eventids: Record<string, number>; sessions: number; source_ips: number; rows_without_src_ip: number;
  protocols: Record<string, number>; first_ts: number | null; last_ts: number | null;
  stripped: { password_fields: number; message_fields: number; ttylog_fields: number };
  sample_rows: Record<string, unknown>[]; usable: boolean; problem: string | null; ml_note: string | null; seconds: number;
  estimated_import_seconds?: number; rows_per_second?: number;
}
interface UploadStatus { state: "validating" | "ready" | "failed"; progress?: number; rows?: number; error?: string; report?: Report }
type Phase = "idle" | "uploading" | "validating" | "preview" | "analyzing" | "done";

const n = (x: number | null | undefined) => (x ?? 0).toLocaleString();
const fmtBytes = (b: number) => (b > 1e9 ? `${(b / 1e9).toFixed(2)} GB` : b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`);
const FIELD_LABEL: Record<string, string> = {
  eventid: "Event type (eventid)", session: "Session ID", timestamp: "Timestamp", src_ip: "Source IP", src_port: "Source port",
  dst_port: "Destination port", protocol: "Protocol", username: "Username", input: "Command text", url: "Download URL",
  shasum: "File hash", duration: "Duration (s)", duration_ms: "Duration (ms)", version: "SSH client", sensor: "Sensor name",
};

async function waitValidation(token: string, onTick: (st: UploadStatus) => void): Promise<{ token: string; report: Report }> {
  for (;;) {
    let st: UploadStatus;
    try {
      st = await api<UploadStatus>(`/datasets/uploads/${token}/process`, { method: "POST" });
    } catch (e) {
      if (e instanceof ApiError && (e.status === 0 || e.status >= 500)) {
        await new Promise((r) => window.setTimeout(r, 3000));
        continue;
      }
      throw e;
    }
    onTick(st);
    if (st.state === "ready" && st.report) return { token, report: st.report };
    if (st.state === "failed") throw new Error(st.error || "Validation failed");
    await new Promise((r) => window.setTimeout(r, 700));
  }
}

async function upload(file: File, onProgress: (p: number) => void): Promise<{ token: string }> {
  const job = await api<{ token: string; chunk_bytes: number }>("/datasets/uploads", {
    method: "POST", body: JSON.stringify({ filename: file.name, size: file.size }),
  });
  for (let offset = 0, part = 0; offset < file.size; offset += job.chunk_bytes, part++) {
    const chunk = file.slice(offset, offset + job.chunk_bytes);
    for (let attempt = 0; ; attempt++) {
      try {
        await uploadChunk(job.token, part, chunk, (p) => onProgress((offset + p * chunk.size) / file.size));
        break;
      } catch (e) {
        if (attempt >= 2) throw e;
        await new Promise((resolve) => window.setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
  }
  await api(`/datasets/uploads/${job.token}/complete`, { method: "POST" });
  return { token: job.token };
}

function uploadChunk(token: string, part: number, chunk: Blob, onProgress: (p: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `/api/datasets/uploads/${token}/chunks/${part}`);
    Object.entries(API_HEADERS).forEach(([k, v]) => xhr.setRequestHeader(k, v));
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      let body: any = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not json */ }
      if (xhr.status >= 200 && xhr.status < 300 && body) return resolve();
      if (xhr.status === 401) window.dispatchEvent(new Event("vs-signed-out"));
      if (xhr.status === 413 && !body) return reject(new Error("The file is larger than the web server allows. Use the command-line importer."));
      reject(new Error(body?.detail || `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error("Upload failed: the API is unreachable."));
    xhr.send(chunk);
  });
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-2xl bg-white/70 p-3">
      <div className="text-xs text-ink-faint">{label}</div>
      <div className="mt-0.5 font-display text-xl font-semibold tabular-nums" style={tone ? { color: tone } : undefined}>{value}</div>
    </div>
  );
}

function Steps({ phase }: { phase: Phase }) {
  const steps = [["uploading", "Uploading"], ["validating", "Validating"], ["preview", "Review"], ["analyzing", "Analyzing"], ["done", "Ready"]] as const;
  const at = steps.findIndex(([k]) => k === phase);
  return (
    <ol className="mb-4 flex flex-wrap gap-2 text-xs" aria-label="Import progress">
      {steps.map(([k, label], i) => (
        <li key={k} className={`rounded-full px-3 py-1 font-semibold ${i < at ? "bg-sev-low/15 text-sev-low" : i === at ? "bg-signal text-white" : "bg-white/60 text-ink-faint"}`}
            aria-current={i === at ? "step" : undefined}>{i + 1}. {label}</li>
      ))}
    </ol>
  );
}

export default function ImportDataset() {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const { datasets, reloadDatasets, setScope } = useScope();
  const input = useRef<HTMLInputElement>(null);
  const [phase, setPhase] = useState<Phase>(() => sessionStorage.getItem("vs-import-dataset") ? "analyzing" : "idle");
  const [pct, setPct] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [tok, setTok] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [rechecking, setRechecking] = useState(false);
  const [val, setVal] = useState<{ progress: number; rows: number }>({ progress: 0, rows: 0 });
  const [name, setName] = useState("");
  const [dsId, setDsId] = useState<number | null>(() => {
    const saved = Number(sessionStorage.getItem("vs-import-dataset"));
    return saved > 0 ? saved : null;
  });
  const [drag, setDrag] = useState(false);
  const running = datasets.find((d) => d.id === dsId) ?? null;

  function accept(r: { token: string; report: Report }) {
    setReport(r.report); setTok(r.token); setMapping(r.report.csv?.mapping ?? {}); setPhase("preview");
  }

  async function choose(f: File) {
    setFile(f); setErr(null); setReport(null); setTok(null); setDsId(null);
    setName(f.name.replace(/(\.(jsonl?|log|csv|tsv|gz|zip))+$/i, ""));
    setPhase("uploading"); setPct(0); setVal({ progress: 0, rows: 0 });
    try {
      const { token } = await upload(f, (p) => setPct(p));
      setPhase("validating");
      accept(await waitValidation(token, (st) => setVal({ progress: st.progress ?? 0, rows: st.rows ?? 0 })));
    } catch (e) { setErr((e as Error).message); setPhase("idle"); }
  }

  async function recheck() {
    if (!tok) return;
    setRechecking(true); setErr(null);
    try {
      await api("/datasets/recheck", { method: "POST", body: JSON.stringify({ token: tok, mapping }) });
      accept(await waitValidation(tok, () => undefined));
    } catch (e) { setErr((e as Error).message); }
    setRechecking(false);
  }

  async function startImport() {
    if (!tok) return;
    setErr(null);
    try {
      const r = await api<{ id: number }>("/datasets/import", { method: "POST", body: JSON.stringify({ token: tok, name: name.trim() || file?.name }) });
      setDsId(r.id); setPhase("analyzing"); reloadDatasets();
      sessionStorage.setItem("vs-import-dataset", String(r.id));
    } catch (e) { setErr((e as Error).message); }
  }

  useEffect(() => {
    if (phase !== "analyzing" || dsId == null) return;
    let cancelled = false;
    let timer: number | undefined;
    const advance = async () => {
      try {
        await api(`/datasets/${dsId}/process`, { method: "POST" });
        const d = await api<Dataset>(`/datasets/${dsId}`);
        if (cancelled) return;
        reloadDatasets();
        setErr(null);
        if (d.status === "ready") { sessionStorage.removeItem("vs-import-dataset"); setPhase("done"); return; }
        if (d.status === "failed") { sessionStorage.removeItem("vs-import-dataset"); setErr(d.error || "Import failed"); setPhase("idle"); return; }
      } catch (e) { if (!cancelled) setErr(`${(e as Error).message} Retrying; saved progress is retained.`); }
      if (!cancelled) timer = window.setTimeout(advance, 1000);
    };
    advance();
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [phase, dsId, reloadDatasets]);

  function open(id: number, path: string) { setScope(`ds:${id}`); navigate(path); }
  async function remove(d: Dataset) {
    if (!window.confirm(`Delete "${d.name}"? Its events, sessions, alerts, verdicts and model are removed. Live sensor data is not affected.`)) return;
    try { await api(`/datasets/${d.id}`, { method: "DELETE" }); reloadDatasets(); } catch (e) { setErr((e as Error).message); }
  }
  const reset = () => { setPhase("idle"); setFile(null); setReport(null); setTok(null); setDsId(null); setErr(null); };
  const canImport = !!report && report.accepted_rows > 0;

  return (
    <>
      <PageHeader title="Import dataset"
        subtitle="Analyze historical Cowrie SSH/Telnet logs before your AWS sensor is running. Imported events go through the same session timeline, detection rules and anomaly ranking as live traffic, and stay labelled as their own data source." />
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 xl:col-span-8">
          {!isAdmin && (
            <div className="glass mb-4 flex items-start gap-3 p-4 text-sm">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-signal" />
              <span>Importing datasets is an admin task. You can analyze any imported dataset listed here: choose it, then use Overview, Alert queue, SSH sessions and Anomaly ranking.</span>
            </div>
          )}
          {isAdmin && phase !== "idle" && <Steps phase={phase} />}
          {err && <div className="mb-4"><ErrorBanner message={err} /></div>}

          {isAdmin && phase === "idle" && (
            <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
                 onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) choose(f); }}
                 className={`glass-strong flex flex-col items-center justify-center gap-3 border-2 border-dashed p-10 text-center transition ${drag ? "border-signal bg-white/90" : "border-signal/25"}`}>
              <UploadCloud className="h-10 w-10 text-signal" />
              <div>
                <p className="font-display text-lg font-semibold">Drop one Cowrie log file here</p>
                <p className="mt-1 text-sm text-ink-soft">JSON Lines, a JSON array, CSV (you confirm the column mapping), or any of these as .gz or .zip.</p>
              </div>
              <button className="btn-primary" onClick={() => input.current?.click()}><FileJson className="h-4 w-4" />Choose file</button>
              <input ref={input} type="file" className="hidden" accept=".json,.jsonl,.log,.csv,.tsv,.gz,.zip,application/json,text/csv"
                     onChange={(e) => { const f = e.target.files?.[0]; if (f) choose(f); e.target.value = ""; }} />
              <p className="max-w-lg text-xs text-ink-faint">Nothing is stored until you confirm the preview. Captured passwords, Cowrie's message field and terminal-log paths are stripped.</p>
            </div>
          )}

          {(phase === "uploading" || phase === "validating") && file && (
            <Card title={phase === "uploading" ? "Uploading" : "Validating every row"}>
              <p className="text-sm text-ink-soft"><span className="mono">{file.name}</span> · {fmtBytes(file.size)}</p>
              <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-ink/5">
                <div className="h-full rounded-full bg-signal transition-all" style={{ width: `${Math.max(2, (phase === "validating" ? val.progress : pct) * 100)}%` }} />
              </div>
              <p className="mt-2 text-xs text-ink-faint">
                {phase === "uploading" ? `${(pct * 100).toFixed(0)}% uploaded`
                  : `${(val.progress * 100).toFixed(0)}% · ${n(val.rows)} rows checked. Each row is validated and sanitized once; the import reuses this work.`}
              </p>
            </Card>
          )}

          {phase === "preview" && report && (
            <div className="flex flex-col gap-4">
              {report.problem && (
                <div role="alert" className={`glass flex items-start gap-3 p-4 text-sm ${report.accepted_rows ? "" : "ring-2 ring-sev-critical/30"}`}>
                  <XCircle className={`mt-0.5 h-5 w-5 shrink-0 ${report.accepted_rows ? "text-sev-medium" : "text-sev-critical"}`} />
                  <div><b className="font-semibold">{report.accepted_rows ? "Check before importing" : "This file can't be imported yet"}</b><p className="mt-0.5 text-ink-soft">{report.problem}</p></div>
                </div>
              )}
              <Card title="Validation preview" action={<button className="btn-ghost py-1.5" onClick={reset}>Choose another file</button>}>
                <p className="text-sm text-ink-soft"><span className="mono">{report.filename}</span> · {report.format.toUpperCase()} · {fmtBytes(report.size_bytes)} · checked in {report.seconds}s</p>
                <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
                  <Stat label="Rows read" value={n(report.total_rows)} />
                  <Stat label="Accepted" value={n(report.accepted_rows)} tone="#1F9E8F" />
                  <Stat label="Rejected" value={n(report.rejected_rows)} tone={report.rejected_rows ? "#D1366B" : undefined} />
                  <Stat label="Sessions" value={n(report.sessions)} />
                </div>
                {report.accepted_rows > 0 && (
                  <div className="mt-3 grid gap-3 text-sm md:grid-cols-2">
                    <div className="rounded-2xl bg-white/60 p-3">
                      <div className="text-xs text-ink-faint">Recorded between</div>
                      <div className="font-medium">{fmtTime(report.first_ts)} → {fmtTime(report.last_ts)}</div>
                      <div className="mt-2 text-xs text-ink-faint">Sources and protocols</div>
                      <div>{n(report.source_ips)} distinct source IP{report.source_ips === 1 ? "" : "s"} · {Object.entries(report.protocols).map(([k, v]) => `${k} ${n(v)}`).join(" · ") || "protocol not recorded"}</div>
                      {report.rows_without_src_ip > 0 && <div className="mt-1 text-xs text-sev-medium">{n(report.rows_without_src_ip)} rows have no source IP; they're kept but can't count toward per-source rules.</div>}
                      {report.prefixed_eventids > 0 && <div className="mt-1 text-xs text-ink-soft">{n(report.prefixed_eventids)} event types had no "cowrie." prefix and were matched to Cowrie events.</div>}
                      {report.ml_note && <div className="mt-1 text-xs text-sev-medium">{report.ml_note}</div>}
                    </div>
                    <div className="rounded-2xl bg-[#E7F7F3] p-3">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-sev-low"><ShieldCheck className="h-4 w-4" />Stripped before saving</div>
                      <ul className="mt-1.5 space-y-0.5 text-sm">
                        <li>{n(report.stripped.password_fields)} captured passwords</li>
                        <li>{n(report.stripped.message_fields)} message fields (Cowrie repeats passwords there)</li>
                        <li>{n(report.stripped.ttylog_fields)} terminal-log paths</li>
                      </ul>
                    </div>
                  </div>
                )}
              </Card>

              {report.csv && (
                <Card title="CSV column mapping" action={<button className="btn-ghost py-1.5" onClick={recheck} disabled={rechecking}>{rechecking ? "Checking…" : "Check again with this mapping"}</button>}>
                  <p className="mb-3 text-sm text-ink-soft">Match your columns to Cowrie fields. Event type, Session ID and Timestamp are required. Password columns are never imported.</p>
                  <div className="grid gap-2 md:grid-cols-2">
                    {report.csv.fields.map((f) => (
                      <label key={f} className="flex items-center gap-2 text-sm">
                        <span className="w-40 shrink-0">{FIELD_LABEL[f] ?? f}{report.csv!.required.includes(f) && <span className="text-sev-critical"> *</span>}</span>
                        <select className="field w-full py-1" value={mapping[f] ?? ""} onChange={(e) => setMapping({ ...mapping, [f]: e.target.value })}>
                          <option value="">Not in this file</option>
                          {report.csv!.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                        </select>
                      </label>
                    ))}
                  </div>
                </Card>
              )}

              {report.rejections.length > 0 && (
                <Card title="Rejected rows">
                  <ul className="flex flex-col gap-2 text-sm">
                    {report.rejections.map((r) => (
                      <li key={r.reason} className="rounded-2xl bg-white/60 p-3">
                        <div className="flex justify-between gap-2"><span className="font-medium">{r.label}</span><span className="tabular-nums text-sev-critical">{n(r.count)}</span></div>
                        {r.samples.map((smp, i) => <div key={i} className="mono mt-1 truncate text-xs text-ink-soft" title={smp.text}>{smp.file}:{smp.line} — {smp.text}</div>)}
                      </li>
                    ))}
                  </ul>
                </Card>
              )}

              {report.accepted_rows > 0 && (
                <Card title="Event types">
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(report.eventids).map(([k, v]) => <span key={k} className="rounded-lg bg-white/80 px-2 py-0.5 text-xs"><span className="mono">{k.replace("cowrie.", "")}</span> <b className="tabular-nums">{n(v)}</b></span>)}
                  </div>
                  <details className="mt-3 text-xs">
                    <summary className="cursor-pointer text-ink-soft">First sanitized rows (exactly what will be stored)</summary>
                    <pre className="mono mt-2 max-h-64 overflow-auto rounded-xl bg-[#F3F7FD] p-3">{report.sample_rows.map((r) => JSON.stringify(r)).join("\n")}</pre>
                  </details>
                </Card>
              )}

              <Card title="Import">
                <div className="flex flex-wrap items-end gap-3">
                  <label className="min-w-[16rem] flex-1 text-sm">
                    <span className="mb-1 block text-xs text-ink-faint">Dataset name (shown wherever its evidence appears)</span>
                    <input className="field w-full" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} disabled={!canImport} />
                  </label>
                  <button className="btn-primary" onClick={startImport} disabled={!canImport || !name.trim()}>
                    {canImport ? `Import and analyze ${n(report.accepted_rows)} rows` : "Nothing valid to import"}
                  </button>
                </div>
                {canImport && <p className="mt-2 text-xs text-ink-faint">
                  {report.rejected_rows > 0 && `The ${n(report.rejected_rows)} rejected rows are skipped. `}Identical duplicate rows are stored once.
                  {report.estimated_import_seconds != null && ` Estimated analysis time: about ${report.estimated_import_seconds < 90 ? `${report.estimated_import_seconds} seconds` : `${Math.round(report.estimated_import_seconds / 60)} minutes`}. You can keep using the dashboard meanwhile.`}
                </p>}
              </Card>
            </div>
          )}

          {(phase === "analyzing" || phase === "done") && running && (
            <Card title={phase === "done" ? "Analysis ready" : "Analyzing"}>
              <div className="flex items-center gap-2 text-sm">
                {phase === "done" ? <CheckCircle2 className="h-5 w-5 shrink-0 text-sev-low" /> : <span className="h-2.5 w-2.5 shrink-0 animate-pulse rounded-full bg-signal" />}
                <span className="font-medium">{running.stage}</span>
              </div>
              <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-ink/5">
                <div className="h-full rounded-full bg-signal transition-all" style={{ width: `${Math.max(3, running.progress * 100)}%` }} />
              </div>
              {phase === "done" && (
                <>
                  <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-3">
                    <Stat label="Rows accepted" value={n(running.accepted_rows)} tone="#1F9E8F" />
                    <Stat label="Rows rejected" value={n(running.rejected_rows)} tone={running.rejected_rows ? "#D1366B" : undefined} />
                    <Stat label="Duplicates skipped" value={n(running.duplicate_rows)} />
                    <Stat label="Sessions created" value={n(running.sessions)} />
                    <Stat label="Alerts generated" value={n(running.alerts)} tone={running.alerts ? "#D2560F" : undefined} />
                    <Stat label="Recorded" value={running.first_ts ? new Date(running.first_ts * 1000).toLocaleDateString() : "—"} />
                  </div>
                  <p className="mt-2 text-xs text-ink-faint">Events from {fmtTime(running.first_ts)} to {fmtTime(running.last_ts)}. The dataset view uses this range automatically.</p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <button className="btn-primary" onClick={() => open(running.id, "/")}>View imported analysis</button>
                    <button className="btn-ghost" onClick={() => open(running.id, "/alerts?status=all")}>Open its alerts</button>
                    <button className="btn-ghost" onClick={() => open(running.id, "/sessions?sort=anomaly")}>Most unusual sessions</button>
                  </div>
                  <button className="mt-3 text-xs font-semibold text-signal" onClick={reset}>Import another file</button>
                </>
              )}
            </Card>
          )}
        </div>

        <div className="col-span-12 xl:col-span-4">
          <Card title="Imported datasets">
            {datasets.length === 0 ? <p className="text-sm text-ink-soft">None yet. Each import becomes its own data source in the sidebar.</p> : (
              <ul className="flex flex-col gap-2">
                {datasets.map((d) => (
                  <li key={d.id} className="rounded-2xl bg-white/65 p-3 text-sm">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate font-semibold">{d.name}</div>
                        <div className="truncate text-xs text-ink-faint">{d.filename} · imported {fmtTime(d.created_at)}</div>
                      </div>
                      {isAdmin && (
                        <button className="rounded-lg p-1 text-ink-faint hover:bg-sev-critical/10 hover:text-sev-critical disabled:opacity-40" title="Delete dataset"
                                disabled={d.status === "importing"} onClick={() => remove(d)} aria-label={`Delete ${d.name}`}><Trash2 className="h-4 w-4" /></button>
                      )}
                    </div>
                    {d.status === "ready" && (
                      <>
                        <div className="mt-1 text-xs text-ink-soft">{n(d.accepted_rows)} rows accepted · {n(d.rejected_rows)} rejected · {n(d.sessions)} sessions · {n(d.alerts)} alerts</div>
                        <div className="text-xs text-ink-faint">Recorded {fmtTime(d.first_ts)} – {fmtTime(d.last_ts)}</div>
                        <div className="mt-2 flex gap-3">
                          <button className="text-xs font-semibold text-signal" onClick={() => open(d.id, "/")}>View analysis</button>
                          <button className="text-xs font-semibold text-signal" onClick={() => open(d.id, "/sessions")}>View imported sessions</button>
                        </div>
                      </>
                    )}
                    {d.status === "importing" && <div className="mt-1 text-xs text-signal">{d.stage} · {(d.progress * 100).toFixed(0)}%
                      {isAdmin && dsId !== d.id && <button className="ml-2 font-semibold" onClick={() => {
                        sessionStorage.setItem("vs-import-dataset", String(d.id)); setDsId(d.id); setPhase("analyzing");
                      }}>Resume analysis</button>}
                    </div>}
                    {d.status === "failed" && <div className="mt-1 text-xs text-sev-critical"><XCircle className="mr-1 inline h-3.5 w-3.5" />{d.error}
                      {isAdmin && <button className="mt-2 block font-semibold text-signal" onClick={async () => {
                        try {
                          await api(`/datasets/${d.id}/retry`, { method: "POST" });
                          sessionStorage.setItem("vs-import-dataset", String(d.id)); setDsId(d.id); setPhase("analyzing"); setErr(null);
                        } catch (e) { setErr((e as Error).message); }
                      }}>Retry analysis</button>}
                    </div>}
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Good files to start with" className="mt-4">
            <ul className="space-y-2 text-sm text-ink-soft">
              <li>Kaggle Cowrie SSH/Telnet honeypot datasets: upload the downloaded .zip directly.</li>
              <li>Your own Cowrie's <span className="mono">var/log/cowrie/cowrie.json*</span>.</li>
              <li>Flow datasets such as CIC-IDS2017 have no sessions or commands, so they don't fit this timeline view.</li>
              <li>Files over 1 GB: use the command-line importer in the README.</li>
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}
