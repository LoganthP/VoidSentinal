export type Severity = "none" | "low" | "medium" | "high" | "critical";
export type Verdict = "investigate" | "routine" | "uncertain" | null;
export type Outcome = "no_auth" | "auth_failed" | "login_no_commands" | "interactive";

export interface Explanation {
  feature: string; label: string; value: number; baseline_median: number; direction: "higher" | "lower"; z: number;
}

export interface Session {
  id: number; sensor: string; session: string; src_ip: string | null; src_port: number | null;
  start_ts: number; end_ts: number; start_iso: string; end_iso: string; status: "open" | "closed";
  closed_reason: string | null; duration: number | null; client_version: string | null; event_count: number;
  login_failed: number; login_success: number; username: string | null; usernames: string[];
  command_count: number; commands_failed: number; categories: string[]; download_count: number;
  outcome: Outcome; is_demo: boolean; max_severity: number; severity: Severity; alert_count: number;
  anomaly_score: number | null; anomaly_pct: number | null; model_version: string | null;
  features: Record<string, number> | null; explanation: Explanation[] | null;
  verdict: Verdict; verdict_note: string | null; verdict_at: number | null;
  dataset_id: number | null; protocol: string | null;
}

export interface Alert {
  id: number; rule_id: string; title: string; severity: Exclude<Severity, "none">; severity_rank: number;
  sensor: string; session_id: number | null; related_sessions: number[]; src_ip: string | null;
  reason: string; evidence?: string[]; evidence_count?: number; first_ts: number; last_ts: number;
  status: "open" | "triaged"; verdict?: Verdict; related_count?: number; outcome?: Outcome; anomaly_pct?: number | null; is_demo?: boolean;
}

export interface TimelineEvent {
  uid: string; eventid: string; ts: number; ts_iso: string; offset_s: number;
  phase: "connect" | "auth" | "shell" | "close" | "other"; title: string; detail: string;
  redacted: boolean; alert_ids: number[];
}

export interface SensorHealth {
  sensor: string; first_seen: number; last_heartbeat_ts: number | null; last_event_ts: number | null;
  shipped_total: number | null; cowrie_log_age_s: number | null; collector_version: string | null;
  state: "active" | "quiet" | "stalled" | "unknown"; note: string; heartbeat_age_s: number | null; event_age_s: number | null;
}
