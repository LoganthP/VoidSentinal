import { FlaskConical, RefreshCw, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, ErrorBanner, PageHeader, Skeleton } from "../components/ui";
import { api, usePoll } from "../lib/api";
import { useScope } from "../lib/scope";
import { useAuth } from "../lib/auth";
import { fmtTime } from "../lib/format";

interface MlStatus {
  active_version: string | null; trained_at: number | null; n_train: number; feature_version: string;
  features: { name: string; label: string }[]; eligible_sessions: number; min_train: number;
  include_demo: boolean; scored_sessions: number;
  history: { version: string; created_at: number; n_train: number; active: number }[];
}
interface Tally { picked: number; reviewed: number; investigate: number; routine: number; uncertain: number; unreviewed: number; precision: number | null }
interface EvalResult {
  ok: boolean; error?: string; caveat?: string; demo_included?: boolean;
  protocol?: { split_ts: number; budget_per_week: number; train_sessions: number; test_sessions: number; feature_version: string; train_from: number; train_to: number };
  totals?: { rules_only: Tally; rules_ml: Tally; ml_only_investigate: number; ml_only_session_ids: number[]; alerts_in_test_period: number;
             reviewed_test_sessions: number; investigate_in_test_period: number; recall_rules_only: number | null; recall_rules_ml: number | null };
  weekly?: { week: string; sessions: number; alerts: number; rules_only: Tally; rules_ml: Tally; ml_surfaced_without_alert: number; ml_only_investigate: number }[];
}

const pct = (x: number | null | undefined) => (x == null ? "—" : `${(x * 100).toFixed(0)}%`);

interface Plan {
  eligible: number; demo_excluded: number; first_ts: number | null; last_ts: number | null; default_split_ts: number | null;
  split_ts: number | null; train: number; test: number; min_train: number; reviewed_total: number; reviewed_test: number;
  investigate_test: number; ready: boolean;
}
/** epoch seconds -> value for <input type="datetime-local"> in the viewer's timezone */
const toLocalInput = (ts: number | null | undefined) => {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const p = (v: number) => String(v).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
};
const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

export default function Models() {
  const { withScope, isDataset, dataset } = useScope();
  const { isAdmin } = useAuth();
  const { data, error, loading, reload } = usePoll<MlStatus>(withScope("/ml/status"), 20000);
  const [training, setTraining] = useState(false);
  const [trainMsg, setTrainMsg] = useState<string | null>(null);
  const [budget, setBudget] = useState(20);
  const [split, setSplit] = useState("");
  const [includeDemo, setIncludeDemo] = useState(false);
  const [result, setResult] = useState<EvalResult | null>(null);
  const planQ = new URLSearchParams();
  if (split) planQ.set("split", new Date(split).toISOString());
  if (includeDemo && !isDataset) planQ.set("include_demo", "true");
  const { data: plan } = usePoll<Plan>(withScope(`/evaluation/plan?${planQ}`));
  const [running, setRunning] = useState(false);

  async function retrain() {
    setTraining(true); setTrainMsg(null);
    try {
      const r = await api<{ trained: boolean; reason?: string; version?: string; n_train?: number; rescored?: number }>(withScope("/ml/retrain"), { method: "POST" });
      setTrainMsg(r.trained ? `Trained ${r.version} on ${r.n_train} sessions and rescored ${r.rescored}.` : r.reason || "Not trained.");
      reload();
    } catch (e) { setTrainMsg((e as Error).message); }
    setTraining(false);
  }

  async function evaluate() {
    setRunning(true);
    try {
      const q = new URLSearchParams({ budget: String(budget) });
      if (split) q.set("split", new Date(split).toISOString()); // local picker time -> UTC
      if (includeDemo && !isDataset) q.set("include_demo", "true");
      setResult(await api<EvalResult>(withScope(`/evaluation?${q}`)));
    } catch (e) { setResult({ ok: false, error: (e as Error).message }); }
    setRunning(false);
  }

  const t = result?.totals;
  const chart = t ? [
    { name: "Worth investigating", "Rules only": t.rules_only.investigate, "Rules + ML": t.rules_ml.investigate },
    { name: "Routine", "Rules only": t.rules_only.routine, "Rules + ML": t.rules_ml.routine },
    { name: "Uncertain", "Rules only": t.rules_only.uncertain, "Rules + ML": t.rules_ml.uncertain },
    { name: "Not yet reviewed", "Rules only": t.rules_only.unreviewed, "Rules + ML": t.rules_ml.unreviewed },
  ] : [];

  return (
    <>
      <PageHeader title="Anomaly ranking"
        subtitle={isDataset
          ? `Sessions in "${dataset?.name}" ranked by how unusual they are compared with the rest of this dataset. The model is trained on this dataset only. Precision needs your verdicts: review sessions, then run the evaluation.`
          : "An Isolation Forest ranks completed sessions by how unusual they are compared with earlier traffic. The evaluation below checks whether that ranking helps you find more sessions worth investigating with the same review effort."} />
      {error && <div className="mb-4"><ErrorBanner message={error} /></div>}

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 lg:col-span-5">
          <Card title="Current model" className="h-full" action={
            isAdmin && <button className="btn-ghost py-1.5" onClick={retrain} disabled={training}>
              <RefreshCw className={`h-4 w-4 ${training ? "animate-spin" : ""}`} />{training ? "Training…" : "Retrain now"}
            </button>}>
            {loading && !data ? <Skeleton className="h-40" /> : data && (
              <div className="flex flex-col gap-3 text-sm">
                {data.active_version ? (
                  <div className="rounded-2xl bg-white/70 p-3">
                    <div className="mono font-medium">{data.active_version}</div>
                    <div className="mt-1 text-xs text-ink-soft">Trained {fmtTime(data.trained_at)} on {data.n_train} completed sessions · {data.scored_sessions} sessions scored</div>
                  </div>
                ) : (
                  <div className="rounded-2xl bg-white/70 p-3">
                    <div className="font-semibold">{isDataset ? "Too few sessions to rank" : "Collecting a baseline"}</div>
                    <div className="mt-1 text-xs text-ink-soft">
                      {isDataset
                        ? `This dataset has ${data.eligible_sessions} completed sessions; anomaly ranking needs at least ${data.min_train}. Rules, timelines and verdicts still work. Import a larger file to rank sessions.`
                        : `${data.eligible_sessions} of ${data.min_train} completed sessions so far. The worker trains automatically once it has enough.`}
                    </div>
                    <div className="mt-2 h-2 overflow-hidden rounded-full bg-ink/5">
                      <div className="h-full rounded-full bg-signal" style={{ width: `${Math.min(100, (data.eligible_sessions / data.min_train) * 100)}%` }} />
                    </div>
                  </div>
                )}
                {trainMsg && <p className="text-xs text-ink-soft">{trainMsg}</p>}
                <p className="text-xs text-ink-faint">
                  {isDataset ? (data.active_version ? "Trained once at import on this dataset's completed sessions only." : "Models for imported data are trained once, at import.") : <>Demo traffic is {data.include_demo ? "included in" : "excluded from"} training (VS_ML_INCLUDE_DEMO). The evaluation excludes it unless you tick "Include demo traffic for a lab check". Retrains automatically when eligible sessions grow 25% or every 6 hours.</>}
                </p>
                <div>
                  <div className="mb-1.5 text-xs text-ink-faint">Features ({data.feature_version}) — each can be checked against the session timeline</div>
                  <div className="flex flex-wrap gap-1.5">{data.features.map((f) => <span key={f.name} className="rounded-lg bg-white/80 px-2 py-0.5 text-xs">{f.label}</span>)}</div>
                </div>
                {data.history.length > 1 && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-ink-soft">Previous models</summary>
                    <ul className="mt-2 flex flex-col gap-1">{data.history.map((h) => <li key={h.version} className="mono">{h.version}{h.active ? " (active)" : ""}</li>)}</ul>
                  </details>
                )}
              </div>
            )}
          </Card>
        </div>

        <div className="col-span-12 lg:col-span-7">
          <Card title="Did ML improve triage?" className="h-full">
            <p className="text-sm text-ink-soft">
              Trains a fresh model on sessions before the split date, then, week by week after it, lets each strategy pick the same number of sessions to review.
              <b className="font-semibold text-ink"> Rules only</b> picks alerted sessions by severity; <b className="font-semibold text-ink">rules + ML</b> ranks every session by severity plus unusualness. Picks are scored against your verdicts.
            </p>
            <div className="mt-4 flex flex-wrap items-end gap-3">
              <label className="text-sm">
                <span className="mb-1 block text-xs text-ink-faint">Review budget per week</span>
                <input type="number" min={1} max={500} className="field w-28" value={budget} onChange={(e) => setBudget(Math.max(1, Number(e.target.value) || 1))} />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-xs text-ink-faint">Split at ({tz})</span>
                <input type="datetime-local" className="field" value={split || toLocalInput(plan?.default_split_ts)}
                       min={toLocalInput(plan?.first_ts)} max={toLocalInput(plan?.last_ts)}
                       onChange={(e) => setSplit(e.target.value)} />
              </label>
              <button className="btn-primary" onClick={evaluate} disabled={running || !plan?.ready}
                      title={plan && !plan.ready ? "The split needs enough sessions on both sides" : undefined}>
                <FlaskConical className="h-4 w-4" />{running ? "Running…" : "Run evaluation"}
              </button>
              {split && <button className="text-xs font-semibold text-signal" onClick={() => setSplit("")}>Use default split</button>}
            </div>
            {plan && (
              <div className="mt-4 grid gap-2 rounded-2xl bg-white/60 p-3 text-sm md:grid-cols-3">
                <div>
                  <div className="text-xs text-ink-faint">Eligible sessions</div>
                  <div className="font-semibold tabular-nums">{plan.eligible}</div>
                  <div className="text-xs text-ink-soft">{plan.first_ts ? `${fmtTime(plan.first_ts)} – ${fmtTime(plan.last_ts)}` : "none yet"}</div>
                  {plan.demo_excluded > 0 && <div className="text-xs text-ink-faint">{plan.demo_excluded} demo sessions not counted</div>}
                </div>
                <div>
                  <div className="text-xs text-ink-faint">{split ? "Your split" : "Default split (median session)"}</div>
                  <div className="font-semibold tabular-nums">{plan.train} train · {plan.test} test</div>
                  <div className={`text-xs ${plan.ready ? "text-sev-low" : "text-sev-critical"}`}>
                    {plan.ready ? "Ready to run" : plan.eligible <= plan.min_train ? `Needs more than ${plan.min_train} sessions` : plan.train < plan.min_train ? `Training side needs ${plan.min_train}; move the split later` : "No sessions after the split; move it earlier"}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-ink-faint">Analyst verdicts</div>
                  <div className="font-semibold tabular-nums">{plan.reviewed_test} in test period</div>
                  <div className="text-xs text-ink-soft">{plan.reviewed_total} reviewed overall · {plan.investigate_test} marked worth investigating after the split</div>
                </div>
              </div>
            )}
            {!isDataset && <label className="mt-3 flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1 h-4 w-4 accent-[#D99A0B]" checked={includeDemo} onChange={(e) => setIncludeDemo(e.target.checked)} />
              <span>
                Include demo traffic for a lab check
                <span className="block text-xs text-ink-faint">Lab check only: confirms the evaluation runs end to end. Results built on your own test sessions are not evidence that ML helps.</span>
              </span>
            </label>}
            <div className="mt-3 flex flex-wrap gap-3 text-sm">
              <Link className="font-semibold text-signal" to="/sessions?sort=anomaly">See the most unusual sessions</Link>
              <Link className="font-semibold text-signal" to="/sessions?verdict=none&sort=anomaly">Review unreviewed sessions</Link>
            </div>
            {result && !result.ok && <div className="mt-4"><ErrorBanner message={result.error || "Evaluation failed"} /></div>}
          </Card>
        </div>

        {result?.ok && t && result.protocol && (
          <>
            {result.demo_included && (
              <div role="status" className="col-span-12 flex items-start gap-3 rounded-[22px] border border-sev-medium/30 bg-[#FFF6E0]/90 p-4 text-sm">
                <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
                <span><b className="font-semibold">Lab check, not a result.</b> This run includes demo sessions you generated yourself. Use it to confirm the pipeline works; report only runs on real attacker traffic with demo traffic excluded.</span>
              </div>
            )}
            {t.rules_only.reviewed + t.rules_ml.reviewed === 0 && (
              <div role="status" className="col-span-12 glass p-4 text-sm">
                <b className="font-semibold">No verdicts to score against yet.</b> None of the {t.rules_only.picked + t.rules_ml.picked} picks in the test period has a verdict, so precision and recall are empty.{" "}
                <Link className="font-semibold text-signal" to="/sessions?verdict=none&sort=anomaly">Review unreviewed sessions</Link>, then run the evaluation again.
              </div>
            )}
            <div className="col-span-12 grid grid-cols-2 gap-4 md:grid-cols-4">
              {[
                ["Precision, rules only", pct(t.rules_only.precision), `${t.rules_only.investigate}/${t.rules_only.reviewed} reviewed picks`],
                ["Precision, rules + ML", pct(t.rules_ml.precision), `${t.rules_ml.investigate}/${t.rules_ml.reviewed} reviewed picks`],
                ["Found only by ML", t.ml_only_investigate, "worth investigating, no rule fired"],
                ["Recall, rules → rules + ML", `${pct(t.recall_rules_only)} → ${pct(t.recall_rules_ml)}`, `of ${t.investigate_in_test_period} sessions marked worth investigating`],
              ].map(([k, v, n]) => (
                <div key={String(k)} className="glass p-4">
                  <div className="text-sm text-ink-soft">{k}</div>
                  <div className="mt-1 font-display text-2xl font-semibold tabular-nums">{v}</div>
                  <div className="mt-1 text-xs text-ink-faint">{n}</div>
                </div>
              ))}
            </div>

            <div className="col-span-12 lg:col-span-6">
              <Card title="What each strategy put in front of you" className="h-full">
                <div className="h-64">
                  <ResponsiveContainer>
                    <BarChart data={chart} margin={{ left: -18 }}>
                      <CartesianGrid stroke="#14223B" strokeOpacity={0.06} vertical={false} />
                      <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#3D4963" }} tickLine={false} axisLine={false} />
                      <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#5F6B84" }} tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={{ borderRadius: 12, fontSize: 12 }} />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Bar dataKey="Rules only" fill="#9B6BF2" radius={[8, 8, 0, 0]} />
                      <Bar dataKey="Rules + ML" fill="#2F6BFF" radius={[8, 8, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <p className="mt-2 text-xs text-ink-faint">{result.caveat}</p>
                {t.ml_only_session_ids.length > 0 && (
                  <p className="mt-2 text-xs">Sessions only ML surfaced: {t.ml_only_session_ids.map((id, i) => <span key={id}>{i > 0 && ", "}<Link className="text-signal" to={`/sessions/${id}`}>#{id}</Link></span>)}</p>
                )}
              </Card>
            </div>

            <div className="col-span-12 lg:col-span-6">
              <Card title="Protocol and weekly results" className="h-full">
                <p className="text-xs text-ink-soft">
                  Trained on {result.protocol.train_sessions} sessions ({fmtTime(result.protocol.train_from)} – {fmtTime(result.protocol.train_to)}), tested on {result.protocol.test_sessions} sessions from {fmtTime(result.protocol.split_ts)}. Budget {result.protocol.budget_per_week} per week. {t.alerts_in_test_period} alerts raised in the test period. Feature set {result.protocol.feature_version}.
                </p>
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="text-left text-ink-faint">
                      <th className="py-1.5 font-medium">Week</th><th className="font-medium">Sessions</th><th className="font-medium">Alerted</th>
                      <th className="font-medium">Rules: hits / reviewed</th><th className="font-medium">+ML: hits / reviewed</th><th className="font-medium">ML-only hits</th>
                    </tr></thead>
                    <tbody>{result.weekly?.map((w) => (
                      <tr key={w.week} className="border-t border-ink/5 tabular-nums">
                        <td className="py-1.5 mono">{w.week}</td><td>{w.sessions}</td><td>{w.alerts}</td>
                        <td>{w.rules_only.investigate} / {w.rules_only.reviewed}</td><td>{w.rules_ml.investigate} / {w.rules_ml.reviewed}</td><td>{w.ml_only_investigate}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              </Card>
            </div>
          </>
        )}
      </div>
    </>
  );
}
