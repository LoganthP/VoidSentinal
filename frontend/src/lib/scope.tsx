import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { usePoll } from "./api";

export interface Dataset {
  id: number; name: string; filename: string; created_at: number; status: "importing" | "ready" | "failed";
  stage: string | null; progress: number; total_rows: number; accepted_rows: number; rejected_rows: number;
  duplicate_rows: number; events: number; sessions: number; alerts: number; first_ts: number | null;
  last_ts: number | null; error: string | null; report: Record<string, unknown> | null;
}

/** "live" = AWS / lab sensor data; "ds:<id>" = one imported dataset. Never mixed. */
export type Scope = "live" | `ds:${number}`;

interface Ctx {
  scope: Scope;
  setScope: (s: Scope) => void;
  datasets: Dataset[];
  dataset: Dataset | null;
  isDataset: boolean;
  withScope: (path: string) => string;
  reloadDatasets: () => void;
}

const ScopeCtx = createContext<Ctx | null>(null);
const KEY = "voidsentinel.scope";

function readStored(): Scope {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "live" || (v && /^ds:\d+$/.test(v))) return v as Scope;
  } catch { /* storage unavailable */ }
  return "live";
}

export function ScopeProvider({ children }: { children: ReactNode }) {
  const [scope, setScopeState] = useState<Scope>(readStored);
  const { data, reload } = usePoll<{ items: Dataset[] }>("/datasets", 8000);
  const datasets = data?.items ?? [];

  const setScope = useCallback((s: Scope) => {
    setScopeState(s);
    try { localStorage.setItem(KEY, s); } catch { /* ignore */ }
  }, []);

  // a deleted dataset falls back to live data
  useEffect(() => {
    if (data && scope !== "live" && !datasets.some((d) => `ds:${d.id}` === scope)) setScope("live");
  }, [data, datasets, scope, setScope]);

  const value = useMemo<Ctx>(() => {
    const dataset = scope === "live" ? null : datasets.find((d) => `ds:${d.id}` === scope) ?? null;
    return {
      scope, setScope, datasets, dataset, isDataset: scope !== "live", reloadDatasets: reload,
      withScope: (path: string) => `${path}${path.includes("?") ? "&" : "?"}scope=${encodeURIComponent(scope)}`,
    };
  }, [scope, setScope, datasets, reload]);

  return <ScopeCtx.Provider value={value}>{children}</ScopeCtx.Provider>;
}

export function useScope() {
  const c = useContext(ScopeCtx);
  if (!c) throw new Error("useScope must be used inside ScopeProvider");
  return c;
}
