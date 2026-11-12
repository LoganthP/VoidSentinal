import { Bell, BrainCircuit, Database, FileUp, LayoutGrid, LogOut, RadioTower, Rows3, ShieldCheck, UserRound } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { usePoll } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtTime } from "../lib/format";
import { useScope, type Scope } from "../lib/scope";

interface Provenance {
  kind: "live" | "dataset"; source: string; traffic: string; detail: string;
  first_ts?: number | null; last_ts?: number | null;
}

function Logo() {
  return (
    <div className="flex items-center gap-3 px-2">
      <svg viewBox="0 0 40 40" className="h-9 w-9" aria-hidden>
        <defs>
          <radialGradient id="vs-g" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#2F6BFF" />
            <stop offset="100%" stopColor="#9B6BF2" />
          </radialGradient>
        </defs>
        <circle cx="20" cy="20" r="18" fill="none" stroke="#2F6BFF" strokeOpacity=".18" strokeWidth="2" />
        <circle cx="20" cy="20" r="11" fill="none" stroke="#2F6BFF" strokeOpacity=".35" strokeWidth="2" />
        <circle cx="20" cy="20" r="4.5" fill="url(#vs-g)" />
        <path d="M20 20 L35 11" stroke="#2F6BFF" strokeWidth="2" strokeLinecap="round" />
      </svg>
      <div>
        <div className="font-display text-[1.05rem] font-semibold tracking-[-0.02em]">VoidSentinel</div>
        <div className="text-[0.72rem] text-ink-faint">SSH decoy triage</div>
      </div>
    </div>
  );
}

function SourcePicker({ compact = false, liveLabel }: { compact?: boolean; liveLabel: string }) {
  const { scope, setScope, datasets } = useScope();
  const ready = datasets.filter((d) => d.status === "ready");
  return (
    <label className={compact ? "flex items-center gap-2" : "block"}>
      <span className={`text-xs text-ink-faint ${compact ? "shrink-0" : "mb-1.5 block"}`}>Data source</span>
      <select className="field w-full py-1.5 text-sm" value={scope} onChange={(e) => setScope(e.target.value as Scope)} aria-label="Data source">
        <option value="live">{liveLabel}</option>
        {ready.length > 0 && (
          <optgroup label="Imported datasets">
            {ready.map((d) => <option key={d.id} value={`ds:${d.id}`}>{d.name}</option>)}
          </optgroup>
        )}
      </select>
    </label>
  );
}

/** Where the evidence on this page comes from — shown on every page. */
function ProvenanceStrip({ p }: { p: Provenance | null }) {
  const { setScope } = useScope();
  if (!p) return null;
  const isDs = p.kind === "dataset";
  const trafficTone = p.traffic === "Real" ? "#1F9E8F" : p.traffic === "Demo" ? "#2F6BFF" : p.traffic === "Mixed" ? "#B37E05" : "#5F6B84";
  return (
    <div role="status" className={`mb-4 flex flex-wrap items-center gap-2 rounded-[20px] border px-4 py-2 text-sm backdrop-blur ${isDs ? "border-[#9B6BF2]/25 bg-[#F1EBFF]/85" : "border-white/80 bg-white/55"}`}>
      {isDs ? <Database className="h-4 w-4 text-[#7A4FE0]" /> : <RadioTower className="h-4 w-4 text-signal" />}
      <span className="font-semibold">Source · {p.source.replace("Imported dataset · ", "Imported: ")}</span>
      <span className="text-ink-faint">|</span>
      <span className="font-semibold" style={{ color: isDs ? "#7A4FE0" : trafficTone }}>Traffic · {p.traffic}</span>
      <span className="min-w-0 flex-1 truncate text-ink-soft">
        {isDs ? `${p.detail} · recorded ${fmtTime(p.first_ts)} – ${fmtTime(p.last_ts)}` : p.detail}
      </span>
      {isDs && <button className="text-xs font-semibold text-[#7A4FE0] hover:underline" onClick={() => setScope("live")}>Switch to live data</button>}
    </div>
  );
}

export default function Layout() {
  const { user, isAdmin, signOut } = useAuth();
  const { withScope, scope } = useScope();
  const { data: health } = usePoll<{ sensors: { state: string }[]; worker_state: string }>("/sensors", 15000);
  const { data: prov } = usePoll<Provenance>(withScope("/provenance"), 30000);
  const { data: liveProv } = usePoll<Provenance>(scope === "live" ? null : "/provenance?scope=live", 0);
  const liveLabel = ((scope === "live" ? prov : liveProv)?.source ?? "Live sensor data").replace(" · file", "").replace(" · CloudWatch Logs", "");

  const NAV = [
    { to: "/", label: "Overview", icon: LayoutGrid, end: true },
    { to: "/alerts", label: "Alert queue", icon: Bell },
    { to: "/sessions", label: "SSH sessions", icon: Rows3 },
    { to: "/ml", label: "Anomaly ranking", icon: BrainCircuit },
    { to: "/sensors", label: "Sensors & rules", icon: RadioTower },
    { to: "/import", label: "Import dataset", icon: FileUp },
    ...(isAdmin ? [{ to: "/access", label: "Access", icon: ShieldCheck }] : []),
  ];
  const stalled = health?.sensors.some((s) => s.state === "stalled") || health?.worker_state === "stalled";
  const pipeline = !health ? "Checking pipeline…" : stalled ? "Pipeline needs attention" : health.sensors.length ? "Pipeline healthy" : "Waiting for first sensor";

  return (
    <div className="mx-auto flex min-h-screen max-w-[1500px] gap-5 p-4 md:p-6">
      <aside className="glass-strong sticky top-6 hidden h-[calc(100vh-3rem)] w-60 shrink-0 flex-col p-4 lg:flex">
        <Logo />
        <nav className="mt-7 flex flex-col gap-1" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}
              className={({ isActive }) => `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${isActive ? "bg-white text-ink shadow-glass" : "text-ink-soft hover:bg-white/60 hover:text-ink"}`}>
              <Icon className="h-[18px] w-[18px]" /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-6"><SourcePicker liveLabel={liveLabel} /></div>
        <div className="mt-auto flex flex-col gap-2">
          <div className="rounded-2xl bg-white/70 p-3 text-xs">
            <div className="flex items-center gap-2 font-semibold">
              <span className="relative flex h-2.5 w-2.5">
                {!stalled && health && <span className="ping-soft absolute inline-flex h-full w-full rounded-full bg-sev-low" />}
                <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${stalled ? "bg-sev-critical" : health ? "bg-sev-low" : "bg-ink-faint"}`} />
              </span>
              {pipeline}
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-2xl bg-white/70 p-3 text-sm">
            <UserRound className="h-4 w-4 text-ink-soft" />
            <div className="min-w-0 flex-1">
              <div className="truncate font-semibold">{user?.username}</div>
              <div className="text-xs capitalize text-ink-faint">{user?.role}</div>
            </div>
            <button onClick={signOut} className="rounded-lg p-1.5 text-ink-soft hover:bg-white hover:text-ink" title="Sign out" aria-label="Sign out">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <nav className="glass mb-3 flex gap-1 overflow-x-auto p-2 lg:hidden" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}
              className={({ isActive }) => `flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-white shadow-glass" : "text-ink-soft"}`}>
              <Icon className="h-4 w-4" /> {label}
            </NavLink>
          ))}
          <button onClick={signOut} className="flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm text-ink-soft"><LogOut className="h-4 w-4" />Sign out</button>
        </nav>
        <div className="glass mb-3 p-2.5 lg:hidden"><SourcePicker compact liveLabel={liveLabel} /></div>
        <ProvenanceStrip p={prov} />
        <main><Outlet /></main>
        <footer className="mt-8 pb-2 text-xs text-ink-faint">
          Passwords and terminal recordings are removed before storage. Command text is redacted and shown as plain text.
        </footer>
      </div>
    </div>
  );
}
