"""Store events and rebuild per-session summaries.

A session summary is always recomputed from *all* stored events of that
session, ordered by event time. This keeps the summary correct even when
events arrive late, out of order, or twice.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone

from .categories import categorize
from .config import settings

HEARTBEAT = "voidsentinel.heartbeat"


def parse_ts(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        v = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return time.time()


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def event_row(uid: str, cw_id: str | None, rec: dict, dataset_id: int | None = None) -> tuple:
    ts = parse_ts(rec.get("timestamp"))
    return (uid, cw_id, rec.get("sensor") or "unknown", rec.get("session"), rec["eventid"], ts, iso(ts),
            rec.get("src_ip"), json.dumps(rec, separators=(",", ":")), time.time(), dataset_id)


INSERT_EVENT = ("INSERT OR IGNORE INTO events(event_uid, cw_event_id, sensor, session, eventid, ts, ts_iso, "
                "src_ip, data, ingested_at, dataset_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)")


def close_duration(ev: dict) -> float | None:
    """Seconds from a cowrie.session.closed event: 'duration' (s, Cowrie 2.x) or 'duration_ms' (3.x)."""
    for key, scale in (("duration", 1.0), ("duration_ms", 1000.0)):
        if ev.get(key) is not None:
            try:
                return float(ev[key]) / scale
            except (TypeError, ValueError):
                pass
    return None


def store_event(conn: sqlite3.Connection, uid: str, cw_id: str | None, rec: dict,
                dataset_id: int | None = None) -> bool:
    """Insert one event. Returns True only if it was new."""
    cur = conn.execute(INSERT_EVENT, event_row(uid, cw_id, rec, dataset_id))
    return cur.rowcount == 1


def update_sensor(conn: sqlite3.Connection, rec: dict) -> None:
    sensor = rec.get("sensor") or "unknown"
    ts = parse_ts(rec.get("timestamp"))
    conn.execute("INSERT OR IGNORE INTO sensors(sensor, first_seen) VALUES (?, ?)", (sensor, ts))
    if rec["eventid"] == HEARTBEAT:
        conn.execute(
            "UPDATE sensors SET last_heartbeat_ts = MAX(COALESCE(last_heartbeat_ts, 0), ?), "
            "shipped_total = ?, cowrie_log_age_s = ?, collector_version = ? WHERE sensor = ?",
            (ts, rec.get("shipped_total"), rec.get("cowrie_log_age_s"),
             rec.get("collector_version"), sensor),
        )
    else:
        conn.execute(
            "UPDATE sensors SET last_event_ts = MAX(COALESCE(last_event_ts, 0), ?) WHERE sensor = ?",
            (ts, sensor),
        )


def load_session_events(conn: sqlite3.Connection, sensor: str, session: str) -> list[dict]:
    rows = conn.execute(
        "SELECT event_uid, eventid, ts, src_ip, data FROM events "
        "WHERE sensor = ? AND session = ? ORDER BY ts, rowid",
        (sensor, session),
    ).fetchall()
    events = []
    for r in rows:
        d = json.loads(r["data"])
        d["_uid"], d["_ts"] = r["event_uid"], r["ts"]
        events.append(d)
    return events


def summarize(events: list[dict]) -> dict:
    """Derive a session summary (pure function: easy to test)."""
    s = {
        "src_ip": None, "src_port": None, "start_ts": None, "end_ts": None,
        "last_event_ts": None, "status": "open", "closed_reason": None, "duration": None,
        "client_version": None, "event_count": len(events), "login_failed": 0,
        "login_success": 0, "username": None, "usernames": [], "command_count": 0,
        "commands_failed": 0, "first_command_ts": None, "categories": [],
        "download_count": 0, "outcome": "no_auth", "mean_gap": 0.0, "protocol": None,
    }
    if not events:
        return s
    names: list[str] = []
    cats: set[str] = set()
    closed_ts = None
    for ev in events:
        eid, ts = ev["eventid"], ev["_ts"]
        s["src_ip"] = s["src_ip"] or ev.get("src_ip")
        s["protocol"] = s["protocol"] or ev.get("protocol")
        if eid == "cowrie.session.connect":
            s["src_port"] = ev.get("src_port")
        elif eid == "cowrie.client.version":
            s["client_version"] = ev.get("version")
        elif eid == "cowrie.login.failed":
            s["login_failed"] += 1
            u = ev.get("username")
            if u is not None and u not in names:
                names.append(u)
        elif eid == "cowrie.login.success":
            s["login_success"] += 1
            s["username"] = ev.get("username")
            u = ev.get("username")
            if u is not None and u not in names:
                names.append(u)
        elif eid == "cowrie.command.input":
            s["command_count"] += 1
            if s["first_command_ts"] is None:
                s["first_command_ts"] = ts
            c = categorize(ev.get("input", ""))
            cats |= c
            if "download" in c:
                s["download_count"] += 1
        elif eid == "cowrie.command.failed":
            s["commands_failed"] += 1
        elif eid == "cowrie.session.file_download" and ev.get("url"):
            # Cowrie also emits file_download for shell redirects (echo x > file);
            # only events with a URL are network downloads.
            s["download_count"] += 1
            cats.add("download")
        elif eid == "cowrie.command.chpasswd":
            cats.add("account")
        elif eid == "cowrie.session.closed":
            closed_ts = ts
            d = close_duration(ev)
            if d is not None:
                s["duration"] = d

    ts_list = [e["_ts"] for e in events]
    s["start_ts"], s["last_event_ts"] = min(ts_list), max(ts_list)
    s["end_ts"] = closed_ts or s["last_event_ts"]
    if closed_ts is not None:
        s["status"], s["closed_reason"] = "closed", "session_closed"
    if s["duration"] is None:
        s["duration"] = max(0.0, s["end_ts"] - s["start_ts"])
    if len(ts_list) > 1:
        gaps = [b - a for a, b in zip(ts_list, ts_list[1:])]
        s["mean_gap"] = sum(gaps) / len(gaps)
    s["usernames"] = names[:25]
    s["categories"] = sorted(cats)
    if s["command_count"] > 0:
        s["outcome"] = "interactive"
    elif s["login_success"] > 0:
        s["outcome"] = "login_no_commands"
    elif s["login_failed"] > 0:
        s["outcome"] = "auth_failed"
    return s


def rebuild_session(conn: sqlite3.Connection, sensor: str, session: str,
                    dataset_id: int | None = None, events: list[dict] | None = None) -> int | None:
    events = events if events is not None else load_session_events(conn, sensor, session)
    if not events:
        return None
    s = summarize(events)
    # imported datasets are historical third-party logs, never your own test traffic
    is_demo = 0 if dataset_id is not None else (1 if settings.is_demo_ip(s["src_ip"]) else 0)
    existing = conn.execute(
        "SELECT id, status, closed_reason FROM sessions WHERE sensor=? AND session=?", (sensor, session)
    ).fetchone()
    # A session closed by idle timeout stays closed unless a real close event arrives.
    if existing and existing["closed_reason"] == "idle_timeout" and s["status"] == "open":
        s["status"], s["closed_reason"] = "closed", "idle_timeout"
    cols = (
        "src_ip", "src_port", "start_ts", "end_ts", "last_event_ts", "status", "closed_reason",
        "duration", "client_version", "event_count", "login_failed", "login_success", "username",
        "usernames", "command_count", "commands_failed", "first_command_ts", "categories",
        "download_count", "outcome", "mean_gap", "protocol",
    )
    values = [json.dumps(s[c]) if c in ("usernames", "categories") else s[c] for c in cols]
    if existing:
        sets = ", ".join(f"{c}=?" for c in cols)
        conn.execute(f"UPDATE sessions SET {sets}, is_demo=?, dataset_id=? WHERE id=?",
                     (*values, is_demo, dataset_id, existing["id"]))
        return existing["id"]
    placeholders = ", ".join("?" for _ in cols)
    cur = conn.execute(
        f"INSERT INTO sessions(sensor, session, {', '.join(cols)}, is_demo, dataset_id) "
        f"VALUES (?, ?, {placeholders}, ?, ?)",
        (sensor, session, *values, is_demo, dataset_id),
    )
    return cur.lastrowid


def close_idle_sessions(conn: sqlite3.Connection, now: float | None = None) -> list[int]:
    now = now or time.time()
    cutoff = now - settings.session_idle_timeout
    rows = conn.execute(
        "SELECT id FROM sessions WHERE status='open' AND dataset_id IS NULL AND last_event_ts < ?", (cutoff,)
    ).fetchall()
    ids = [r["id"] for r in rows]
    for sid in ids:
        conn.execute(
            "UPDATE sessions SET status='closed', closed_reason='idle_timeout' WHERE id=?", (sid,)
        )
    return ids
