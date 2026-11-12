import type { Outcome, Severity } from "./types";

export const fmtTime = (ts?: number | null) =>
  ts ? new Date(ts * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";

export const fmtClock = (ts?: number | null) =>
  ts ? new Date(ts * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";

export function fmtAgo(seconds?: number | null) {
  if (seconds == null) return "never";
  if (seconds < 60) return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

export function fmtDuration(s?: number | null) {
  if (s == null) return "—";
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${Math.round(s % 60)}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

export const OUTCOME: Record<Outcome, { label: string; hint: string; color: string }> = {
  no_auth: { label: "Left before login", hint: "Connected and disconnected without trying a password", color: "#8FA3C4" },
  auth_failed: { label: "Login failures only", hint: "Tried passwords, none accepted", color: "#9B6BF2" },
  login_no_commands: { label: "Logged in, no commands", hint: "Accepted by the decoy, then left", color: "#5B8DEF" },
  interactive: { label: "Ran commands", hint: "Reached the emulated shell and typed commands", color: "#E0631A" },
};

export const SEVERITY: Record<Severity, { label: string; color: string; bg: string }> = {
  none: { label: "No alert", color: "#8592AA", bg: "rgba(133,146,170,.12)" },
  low: { label: "Low", color: "#1F9E8F", bg: "rgba(31,158,143,.12)" },
  medium: { label: "Medium", color: "#B37E05", bg: "rgba(217,154,11,.14)" },
  high: { label: "High", color: "#D2560F", bg: "rgba(224,99,26,.13)" },
  critical: { label: "Critical", color: "#D1366B", bg: "rgba(209,54,107,.13)" },
};

export const VERDICT = {
  investigate: { label: "Worth investigating", color: "#D1366B" },
  routine: { label: "Routine", color: "#1F9E8F" },
  uncertain: { label: "Uncertain", color: "#B37E05" },
} as const;
