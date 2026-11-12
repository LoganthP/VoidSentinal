import { useCallback, useEffect, useRef, useState } from "react";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** Every request carries the session cookie (same origin) and, for writes, the
 *  X-VS-Request header the API requires as cross-site-request protection. */
export const API_HEADERS = { "X-VS-Request": "1" };

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      credentials: "same-origin",
      ...init,
      headers: { "Content-Type": "application/json", ...API_HEADERS, ...(init?.headers || {}) },
    });
  } catch {
    throw new ApiError(0, "The API is unreachable. Check that the api container (or uvicorn) is running.");
  }
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    window.dispatchEvent(new Event("vs-signed-out"));
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { const body = await res.json(); if (typeof body?.detail === "string") msg = body.detail; } catch { /* not json */ }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

/** Fetch on mount, when the path changes, and every `intervalMs` while the tab is visible. */
export function usePoll<T>(path: string | null, intervalMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const live = useRef(true);

  const load = useCallback(async (background = false) => {
    if (!path) return;
    if (!background) setLoading(true);
    try {
      const d = await api<T>(path);
      if (live.current) { setData(d); setError(null); }
    } catch (e) {
      if (live.current) setError((e as Error).message);
    } finally {
      if (live.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    live.current = true;
    load();
    if (!intervalMs) return () => { live.current = false; };
    const id = window.setInterval(() => { if (document.visibilityState === "visible") load(true); }, intervalMs);
    return () => { live.current = false; window.clearInterval(id); };
  }, [load, intervalMs]);

  const reload = useCallback(() => load(false), [load]);
  return { data, error, loading, reload, setData };
}
