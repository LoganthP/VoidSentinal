import { AlertTriangle, Inbox } from "lucide-react";
import type { ReactNode } from "react";
import { OUTCOME, SEVERITY, VERDICT } from "../lib/format";
import type { Outcome, Severity, Verdict } from "../lib/types";

export function Card({ title, action, children, className = "" }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`glass p-5 ${className}`}>
      {(title || action) && (
        <header className="mb-4 flex items-center justify-between gap-3">
          {title && <h2 className="h-card">{title}</h2>}
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity] ?? SEVERITY.none;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold" style={{ color: s.color, background: s.bg }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

export function OutcomePill({ outcome }: { outcome: Outcome }) {
  const o = OUTCOME[outcome];
  if (!o) return null;
  return (
    <span title={o.hint} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-white/80 px-2.5 py-0.5 text-xs font-medium text-ink-soft ring-1 ring-white">
      <span className="h-2 w-2 rounded-[3px]" style={{ background: o.color }} />
      {o.label}
    </span>
  );
}

export function VerdictTag({ verdict }: { verdict: Verdict | undefined }) {
  if (!verdict) return <span className="text-xs text-ink-faint">Not reviewed</span>;
  const v = VERDICT[verdict];
  return <span className="text-xs font-semibold" style={{ color: v.color }}>{v.label}</span>;
}

export function DemoTag() {
  return (
    <span title="Controlled test traffic — excluded from the ML evaluation" className="rounded-md bg-signal-soft px-1.5 py-0.5 text-[0.68rem] font-semibold text-signal">
      demo
    </span>
  );
}

/** Anomaly percentile: how unusual vs. the training baseline. */
export function ScoreBar({ pct }: { pct: number | null | undefined }) {
  if (pct == null) return <span className="text-xs text-ink-faint" title="No baseline model yet, or session still open">—</span>;
  const hue = pct >= 95 ? "#D1366B" : pct >= 80 ? "#E0631A" : pct >= 50 ? "#D99A0B" : "#1F9E8F";
  return (
    <div className="flex items-center gap-2" title={`Unusualness ${pct.toFixed(0)}: more unusual than ${pct.toFixed(0)}% of the sessions the model was trained on. Ranks behaviour, not maliciousness.`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-ink/10">
        <div className="h-full rounded-full" style={{ width: `${Math.max(4, pct)}%`, background: hue }} />
      </div>
      <span className="w-9 text-right text-xs font-semibold tabular-nums" style={{ color: hue }}>{pct.toFixed(0)}</span>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      <Inbox className="h-7 w-7 text-ink-faint" />
      <p className="font-display font-semibold">{title}</p>
      {children && <div className="max-w-md text-sm text-ink-soft">{children}</div>}
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div role="alert" className="glass flex items-start gap-3 border-sev-critical/20 p-4 text-sm">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical" />
      <span>{message}</span>
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-xl bg-white/60 ${className}`} />;
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="h-title">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-ink-soft">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
