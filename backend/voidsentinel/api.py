"""VoidSentinel analyst API (served privately behind the dashboard)."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from . import __version__, auth, db, evaluation, importer, ml
from .categories import CATEGORY_LABELS
from .config import settings
from .sessions import close_duration, iso

from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(_app):
    db.init()
    auth.seed_users()
    importer.mark_interrupted()
    importer.cleanup_uploads()
    yield


app = FastAPI(title="VoidSentinel API", version=__version__, lifespan=_lifespan)

import logging as _logging
import sqlite3 as _sqlite3

from fastapi.responses import JSONResponse

_log = _logging.getLogger("vs.api")


@app.exception_handler(_sqlite3.OperationalError)
async def _db_busy(_request, exc):
    msg = str(exc)
    if "locked" in msg or "busy" in msg:
        return JSONResponse(status_code=503, content={
            "detail": "The database is busy (an import may be finishing a step). Try again in a few seconds."})
    _log.exception("database error")
    return JSONResponse(status_code=500, content={"detail": f"Database error: {msg}"})


@app.exception_handler(Exception)
async def _unexpected(_request, exc):
    _log.exception("unhandled error")
    return JSONResponse(status_code=500, content={"detail": f"Unexpected server error: {type(exc).__name__}. "
                                                            "Details are in the api logs."})

RULE_CATALOG = [
    {"id": "AUTH_BRUTE_SESSION", "title": "Password guessing in one connection", "severity": "medium",
     "trigger": f"{settings.brute_session_threshold} or more failed logins within one SSH/Telnet session",
     "attack": "T1110.001 Password Guessing"},
    {"id": "AUTH_BRUTE_SOURCE", "title": "Repeated login failures across connections", "severity": "medium (high at 5× threshold)",
     "trigger": f"{settings.brute_source_threshold} or more failed logins from one source across 2 or more connections, "
                f"with no pause longer than {settings.brute_source_window}s",
     "attack": "T1110 Brute Force"},
    {"id": "INTERACTIVE_ACCESS", "title": "Login followed by shell commands", "severity": "low",
     "trigger": "the decoy accepted a login and at least one command was typed", "attack": None},
    {"id": "PAYLOAD_DOWNLOAD", "title": "Download attempt in the emulated shell", "severity": "high",
     "trigger": "a wget/curl/tftp-style command, or a Cowrie file-download event with a URL",
     "attack": "T1105 Ingress Tool Transfer"},
    {"id": "DROPPER_CHAIN", "title": "Download followed by execution attempt", "severity": "critical",
     "trigger": "a download command followed later in the same session by chmod +x, ./file or sh file",
     "attack": "T1105 then T1059.004 Unix Shell"},
    {"id": "PERSISTENCE", "title": "Persistence attempt", "severity": "high",
     "trigger": "commands touching crontab, authorized_keys, rc.local, init scripts or shell profiles",
     "attack": "T1053.003 Cron / T1098.004 SSH Authorized Keys"},
    {"id": "ACCOUNT_TAMPERING", "title": "Account or password change", "severity": "high",
     "trigger": "passwd, chpasswd, useradd, usermod and similar, or Cowrie's chpasswd event",
     "attack": "T1098 Account Manipulation"},
    {"id": "MINER_INDICATOR", "title": "Crypto-miner indicators", "severity": "high",
     "trigger": "xmrig, stratum URLs or known mining pools in a command", "attack": "T1496 Resource Hijacking"},
    {"id": "DEFENSE_EVASION", "title": "History or log tampering", "severity": "medium",
     "trigger": "history -c, HISTFILE changes, deleting logs, disabling firewalls",
     "attack": "T1070.003 Clear Command History"},
    {"id": "RECON_BURST", "title": "System reconnaissance", "severity": "low",
     "trigger": f"{settings.recon_threshold} or more host, CPU, user or network discovery commands",
     "attack": "T1082 System Information Discovery"},
]
SEVERITY_NAMES = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}


api = APIRouter(prefix="/api", dependencies=[Depends(auth.current_user)])


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


# ------------------------------------------------------------------ sign-in (outside the authenticated router)
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@app.post("/api/auth/login")
def auth_login(body: LoginIn, request: Request, response: Response):
    if request.headers.get("x-vs-request") != "1":
        raise HTTPException(403, "Missing X-VS-Request header")
    return auth.login(request, response, body.username.strip(), body.password)


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    auth.logout(request, response)
    return {"ok": True}


@app.get("/api/auth/me")
def auth_me(request: Request):
    """The signed-in user, or null (200) when signed out, so the sign-in page loads without errors."""
    try:
        return auth.current_user(request)
    except HTTPException as exc:
        if exc.status_code == 401:
            return None
        raise


# ------------------------------------------------------------------ helpers
def _conn():
    return db.get_conn()


def _scope(scope: Optional[str], col: str = "dataset_id") -> tuple[str, list]:
    try:
        return db.scope_sql(scope, col)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


def _dataset_out(row) -> dict:
    d = db.row_to_dict(row)
    d.pop("stats", None)
    d.pop("pid", None)
    if isinstance(d.get("report"), str):
        try:
            d["report"] = json.loads(d["report"])
        except json.JSONDecodeError:
            d["report"] = None
    return d


def _session_out(row) -> dict:
    d = db.row_to_dict(row)
    d["start_iso"], d["end_iso"] = iso(d.get("start_ts")), iso(d.get("end_ts"))
    d["severity"] = SEVERITY_NAMES.get(d.get("max_severity") or 0, "none")
    d["is_demo"] = bool(d.get("is_demo"))
    return d


def sensor_health(row, now: float) -> dict:
    d = dict(row)
    hb, ev = d.get("last_heartbeat_ts"), d.get("last_event_ts")
    if hb is None:
        state, note = "unknown", "No heartbeat received yet"
    elif now - hb > settings.heartbeat_stale_seconds:
        state, note = "stalled", f"Collector silent for {int(now - hb)}s — check the sensor"
    elif ev is None or now - ev > 3600:
        state, note = "quiet", "Collector healthy, no attacker traffic in the last hour"
    else:
        state, note = "active", "Collector healthy and receiving traffic"
    d.update(state=state, note=note,
             heartbeat_age_s=None if hb is None else round(now - hb, 1),
             event_age_s=None if ev is None else round(now - ev, 1))
    return d


PHASE = {
    "cowrie.session.connect": "connect", "cowrie.client.version": "connect",
    "cowrie.client.kex": "connect", "cowrie.client.size": "shell", "cowrie.client.var": "shell",
    "cowrie.login.success": "auth", "cowrie.login.failed": "auth",
    "cowrie.command.input": "shell", "cowrie.command.failed": "shell",
    "cowrie.session.file_download": "shell", "cowrie.command.chpasswd": "shell", "cowrie.session.file_upload": "shell",
    "cowrie.session.params": "shell", "cowrie.direct-tcpip.request": "shell",
    "cowrie.session.closed": "close", "cowrie.log.closed": "close",
}


def describe(ev: dict) -> tuple[str, str]:
    e = ev.get("eventid", "")
    if e == "cowrie.session.connect":
        return "Connection opened", f"{ev.get('src_ip')}:{ev.get('src_port')} → port {ev.get('dst_port')}"
    if e == "cowrie.client.version":
        return "Client identified", str(ev.get("version", ""))
    if e == "cowrie.client.kex":
        return "Key exchange", f"HASSH {ev.get('hassh', '—')}"
    if e == "cowrie.login.failed":
        return "Login failed", f"username '{ev.get('username')}' (password not stored)"
    if e == "cowrie.login.success":
        return "Login accepted by decoy", f"username '{ev.get('username')}' (password not stored)"
    if e == "cowrie.command.input":
        return "Command", ev.get("input", "")
    if e == "cowrie.command.failed":
        return "Command not found", ev.get("input", "")
    if e == "cowrie.session.file_download":
        if ev.get("url"):
            return "File download", f"{ev.get('url')} sha256={str(ev.get('shasum', ''))[:16]}…"
        return "File written", f"{ev.get('destfile', '?')} sha256={str(ev.get('shasum', ''))[:16]}…"
    if e == "cowrie.command.chpasswd":
        return "Password change attempt", f"for user '{ev.get('username')}' (new password not stored)"
    if e == "cowrie.client.size":
        return "Terminal size", f"{ev.get('width', '?')}×{ev.get('height', '?')}"
    if e == "cowrie.client.var":
        return "Client environment variable", ""
    if e == "cowrie.session.params":
        return "Terminal parameters", f"arch {ev.get('arch', '?')}"
    if e == "cowrie.direct-tcpip.request":
        return "Port-forward request", f"to {ev.get('dst_ip')}:{ev.get('dst_port')}"
    if e == "cowrie.session.closed":
        d = close_duration(ev)
        return "Connection closed", f"after {d:.1f}s" if d is not None else "duration not recorded"
    if e == "cowrie.log.closed":
        return "Terminal log closed", "recording not exported"
    return e.replace("cowrie.", ""), ""


# ------------------------------------------------------------------ overview
@api.get("/overview")
def overview(hours: int = Query(24, ge=1, le=24 * 90), scope: str = "live"):
    conn, now = _conn(), time.time()
    w, wa = _scope(scope)
    dataset = None
    if scope.startswith("ds:"):
        dataset = conn.execute("SELECT * FROM datasets WHERE id=?", (wa[0],)).fetchone()
        if not dataset:
            raise HTTPException(404, "Dataset not found")
    if dataset is not None and dataset["stats"]:
        # imported data never changes: serve the summary computed at import time (instant)
        st = json.loads(dataset["stats"])
        w, wa = _scope(scope)
        open_alerts = conn.execute(
            f"SELECT severity, COUNT(*) c FROM alerts WHERE status='open' AND {w} GROUP BY severity", wa).fetchall()
        recent = [db.row_to_dict(r) for r in conn.execute(
            f"SELECT * FROM alerts WHERE status='open' AND {w} ORDER BY severity_rank DESC, last_ts DESC LIMIT 6", wa)]
        for a in recent:
            a.pop("evidence", None)
        return {
            "scope": scope, "dataset": _dataset_out(dataset), "window_hours": None,
            "window": {"from": dataset["first_ts"], "to": dataset["last_ts"]}, "generated_at": now,
            **{k: st[k] for k in ("sessions", "events", "series", "top_sources", "top_usernames", "top_commands")},
            "open_alerts": {r["severity"]: r["c"] for r in open_alerts}, "recent_alerts": recent,
            "sensors": [sensor_health(r, now) for r in conn.execute("SELECT * FROM sensors ORDER BY sensor")],
            "worker": db.get_checkpoint("worker_status"),
            "ml": {"active_version": ml.active_model(conn, scope)[0]},
        }
    if dataset is not None:
        # historical data: the window is the dataset's own time range, not "the last N hours"
        since = dataset["first_ts"] or 0
        until = dataset["last_ts"] or since
        span = max(until - since, 1)
        # pick a bucket that gives a readable number of points for the recorded span
        bucket = (10 if span <= 900 else 60 if span <= 6 * 3600 else 3600 if span <= 3 * 86400
                  else 86400 if span <= 180 * 86400 else 7 * 86400)
    else:
        since, until = now - hours * 3600, now
        bucket = 3600 if hours <= 72 else 86400
    s = conn.execute(
        f"""SELECT COUNT(*) total,
                  SUM(outcome='interactive') interactive, SUM(outcome='auth_failed') auth_failed,
                  SUM(outcome='no_auth') no_auth, SUM(outcome='login_no_commands') login_no_commands,
                  COUNT(DISTINCT src_ip) sources, SUM(is_demo) demo
           FROM sessions WHERE start_ts >= ? AND {w}""", (since, *wa)).fetchone()
    ev = conn.execute(
        f"""SELECT SUM(eventid='cowrie.login.failed') failed, SUM(eventid='cowrie.login.success') success,
                  SUM(eventid='cowrie.command.input') commands
           FROM events WHERE {w} AND eventid IN ('cowrie.login.failed','cowrie.login.success','cowrie.command.input')
           AND ts >= ?""", (*wa, since)).fetchone()
    open_alerts = conn.execute(
        f"SELECT severity, COUNT(*) c FROM alerts WHERE status='open' AND {w} GROUP BY severity", wa).fetchall()

    start_bucket = int(since // bucket) * bucket
    series = {b: {"t": b, "connections": 0, "failed_logins": 0, "commands": 0}
              for b in range(start_bucket, int(until) + 1, bucket)}
    for r in conn.execute(
        f"""SELECT CAST(ts / ? AS INTEGER) * ? b, eventid, COUNT(*) c FROM events
           WHERE ts >= ? AND {w} AND eventid IN ('cowrie.session.connect','cowrie.login.failed','cowrie.command.input')
           GROUP BY b, eventid""", (bucket, bucket, since, *wa)):
        key = {"cowrie.session.connect": "connections", "cowrie.login.failed": "failed_logins",
               "cowrie.command.input": "commands"}[r["eventid"]]
        if r["b"] in series:
            series[r["b"]][key] = r["c"]

    top_sources = [dict(r) for r in conn.execute(
        f"""SELECT src_ip, COUNT(*) sessions, SUM(login_failed) failed_logins, SUM(command_count) commands,
                  MAX(max_severity) max_severity, MAX(is_demo) is_demo
           FROM sessions WHERE start_ts >= ? AND src_ip IS NOT NULL AND {w}
           GROUP BY src_ip ORDER BY sessions DESC, failed_logins DESC LIMIT 8""", (since, *wa))]
    top_users = [dict(r) for r in conn.execute(
        f"""SELECT json_extract(data, '$.username') username, COUNT(*) attempts,
                  SUM(eventid='cowrie.login.success') accepted
           FROM events WHERE ts >= ? AND {w} AND eventid IN ('cowrie.login.failed','cowrie.login.success')
           GROUP BY username ORDER BY attempts DESC LIMIT 8""", (since, *wa))]
    top_cmds = [dict(r) for r in conn.execute(
        f"""SELECT json_extract(data, '$.input') command, COUNT(*) count FROM events
           WHERE ts >= ? AND {w} AND eventid='cowrie.command.input'
           GROUP BY command ORDER BY count DESC LIMIT 8""", (since, *wa))]
    recent_alerts = [db.row_to_dict(r) for r in conn.execute(
        f"SELECT * FROM alerts WHERE status='open' AND {w} ORDER BY severity_rank DESC, last_ts DESC LIMIT 6", wa)]
    for a in recent_alerts:
        a.pop("evidence", None)

    return {
        "scope": scope, "dataset": _dataset_out(dataset) if dataset is not None else None,
        "window_hours": hours if dataset is None else None, "window": {"from": since, "to": until},
        "generated_at": now,
        "sessions": {k: (s[k] or 0) for k in s.keys()},
        "events": {k: (ev[k] or 0) for k in ev.keys()},
        "open_alerts": {r["severity"]: r["c"] for r in open_alerts},
        "series": {"bucket_seconds": bucket, "points": list(series.values())},
        "top_sources": top_sources, "top_usernames": top_users, "top_commands": top_cmds,
        "recent_alerts": recent_alerts,
        "sensors": [sensor_health(r, now) for r in conn.execute("SELECT * FROM sensors ORDER BY sensor")],
        "worker": db.get_checkpoint("worker_status"),
        "ml": {"active_version": ml.active_model(conn, scope if dataset is not None else "live")[0]},
    }


@api.get("/sensors")
def sensors():
    conn, now = _conn(), time.time()
    worker = db.get_checkpoint("worker_status") or {}
    last = worker.get("last_pass_ts")
    return {
        "sensors": [sensor_health(r, now) for r in conn.execute("SELECT * FROM sensors ORDER BY sensor")],
        "worker": worker,
        "worker_state": "unknown" if not last else ("stalled" if now - last > 60 else "running"),
    }


# ------------------------------------------------------------------ sessions
@api.get("/sessions")
def list_sessions(
    q: Optional[str] = None,
    outcome: Optional[str] = None,
    verdict: Optional[str] = None,
    has_alert: Optional[bool] = None,
    min_pct: Optional[float] = None,
    hours: Optional[int] = Query(None, ge=1),
    demo: Literal["include", "exclude", "only"] = "include",
    status: Optional[Literal["open", "closed"]] = None,
    sort: Literal["recent", "anomaly", "severity"] = "recent",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    scope: str = "live",
):
    sw, sa = _scope(scope)
    where, args = [sw], list(sa)
    if q and q.strip():
        like = f"%{q.strip()}%"
        ew, ea = _scope(scope, "e.dataset_id")
        where.append(f"""(src_ip LIKE ? OR session LIKE ? OR username LIKE ? OR usernames LIKE ?
                        OR id IN (SELECT s2.id FROM events e JOIN sessions s2 ON s2.sensor=e.sensor AND s2.session=e.session
                                  WHERE {ew} AND e.eventid='cowrie.command.input'
                                  AND json_extract(e.data,'$.input') LIKE ?))""")
        args += [like] * 4 + ea + [like]
    if outcome:
        where.append("outcome = ?"); args.append(outcome)
    if verdict == "none":
        where.append("verdict IS NULL")
    elif verdict:
        where.append("verdict = ?"); args.append(verdict)
    if has_alert is True:
        where.append("alert_count > 0")
    elif has_alert is False:
        where.append("alert_count = 0")
    if min_pct is not None:
        where.append("anomaly_pct >= ?"); args.append(min_pct)
    if hours:
        where.append("start_ts >= ?"); args.append(time.time() - hours * 3600)
    if demo == "exclude":
        where.append("is_demo = 0")
    elif demo == "only":
        where.append("is_demo = 1")
    if status:
        where.append("status = ?"); args.append(status)
    order = {
        "recent": "start_ts DESC",
        "anomaly": "anomaly_pct DESC, id DESC",
        "severity": "max_severity DESC, alert_count DESC, start_ts DESC",
    }[sort]
    w = " AND ".join(where)
    conn = _conn()
    total = conn.execute(f"SELECT COUNT(*) c FROM sessions WHERE {w}", args).fetchone()["c"]
    rows = conn.execute(f"SELECT * FROM sessions WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?",
                        (*args, limit, offset)).fetchall()
    return {"total": total, "items": [_session_out(r) for r in rows]}


@api.get("/sessions/{session_id}")
def get_session(session_id: int):
    conn = _conn()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Session not found")
    sess = _session_out(row)
    alerts = [db.row_to_dict(a) for a in conn.execute(
        """SELECT a.* FROM alerts a JOIN alert_sessions m ON m.alert_id = a.id
           WHERE m.session_id = ? ORDER BY a.severity_rank DESC, a.first_ts""", (session_id,))]
    for a in alerts:
        a["related_count"] = conn.execute("SELECT COUNT(*) c FROM alert_sessions WHERE alert_id=?",
                                          (a["id"],)).fetchone()["c"]
    evidence_map: dict[str, list[int]] = {}
    for a in alerts:
        for uid in a.get("evidence") or []:
            evidence_map.setdefault(uid, []).append(a["id"])
    events = []
    MAX_EVENTS = 1500  # brute-force sessions can hold tens of thousands of attempts
    total_events = row["event_count"] or 0
    for r in conn.execute(
        "SELECT event_uid, eventid, ts, data FROM events WHERE sensor=? AND session=? ORDER BY ts, rowid LIMIT ?",
        (row["sensor"], row["session"], MAX_EVENTS)):
        data = json.loads(r["data"])
        title, detail = describe(data)
        events.append({
            "uid": r["event_uid"], "eventid": r["eventid"], "ts": r["ts"], "ts_iso": iso(r["ts"]),
            "offset_s": round(r["ts"] - (row["start_ts"] or r["ts"]), 3),
            "phase": PHASE.get(r["eventid"], "other"), "title": title, "detail": detail,
            "redacted": bool(data.get("vs_redacted")), "alert_ids": evidence_map.get(r["event_uid"], []),
        })
    sw, sa = ("dataset_id = ?", [row["dataset_id"]]) if row["dataset_id"] is not None else ("dataset_id IS NULL", [])
    same_src = conn.execute(
        f"SELECT COUNT(*) c, MIN(start_ts) first FROM sessions WHERE src_ip=? AND {sw}", (row["src_ip"], *sa)).fetchone()
    ds = conn.execute("SELECT id, name, filename, created_at FROM datasets WHERE id=?",
                      (row["dataset_id"],)).fetchone() if row["dataset_id"] is not None else None
    return {
        "session": sess, "events": events, "alerts": alerts,
        "events_truncated": max(0, total_events - len(events)),
        "provenance": ({"kind": "dataset", **dict(ds)} if ds else {"kind": "live", "sensor": row["sensor"]}),
        "source_context": {"sessions_from_source": same_src["c"], "first_seen": same_src["first"]},
        "category_labels": CATEGORY_LABELS,
    }


class VerdictIn(BaseModel):
    verdict: Optional[Literal["investigate", "routine", "uncertain"]] = None
    note: Optional[str] = Field(default=None, max_length=2000)


@api.post("/sessions/{session_id}/verdict")
def set_verdict(session_id: int, body: VerdictIn, user: dict = Depends(auth.current_user)):
    with db.tx() as conn:
        cur = conn.execute(
            "UPDATE sessions SET verdict=?, verdict_note=?, verdict_at=?, verdict_by=? WHERE id=?",
            (body.verdict, body.note, time.time() if body.verdict else None,
             user["username"] if body.verdict else None, session_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Session not found")
        conn.execute(
            """UPDATE alerts SET status=?, updated_at=?
               WHERE id IN (SELECT alert_id FROM alert_sessions WHERE session_id = ?)""",
            ("triaged" if body.verdict else "open", time.time(), session_id))
    conn = _conn()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    out = _session_out(row)
    out["alerts_updated"] = conn.execute("SELECT COUNT(*) c FROM alert_sessions WHERE session_id=?",
                                         (session_id,)).fetchone()["c"]
    return out


# ------------------------------------------------------------------ alerts
@api.get("/alerts")
def list_alerts(
    status: Literal["open", "triaged", "all"] = "open",
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    scope: str = "live",
):
    sw, sa = _scope(scope, "a.dataset_id")
    where, args = [sw], list(sa)
    if status != "all":
        where.append("a.status = ?"); args.append(status)
    if severity:
        where.append("a.severity = ?"); args.append(severity)
    if rule_id:
        where.append("a.rule_id = ?"); args.append(rule_id)
    w = " AND ".join(where)
    conn = _conn()
    total = conn.execute(f"SELECT COUNT(*) c FROM alerts a WHERE {w}", args).fetchone()["c"]
    rows = conn.execute(
        f"""SELECT a.*, s.verdict, s.outcome, s.anomaly_pct, s.is_demo FROM alerts a
            LEFT JOIN sessions s ON s.id = a.session_id WHERE {w}
            ORDER BY a.severity_rank DESC, a.last_ts DESC LIMIT ? OFFSET ?""", (*args, limit, offset)).fetchall()
    items = []
    for r in rows:
        d = db.row_to_dict(r)
        d["evidence_count"] = len(d.pop("evidence") or [])
        d["first_iso"], d["last_iso"] = iso(d["first_ts"]), iso(d["last_ts"])
        d["is_demo"] = bool(d.get("is_demo"))
        items.append(d)
    counts = {r["status"]: r["c"] for r in conn.execute(
        f"SELECT a.status, COUNT(*) c FROM alerts a WHERE {sw} GROUP BY a.status", sa)}
    return {"total": total, "items": items, "counts": counts}


# ------------------------------------------------------------------ ML + evaluation
def _model_scope(scope: str) -> str:
    _scope(scope)
    if scope == "all":
        raise HTTPException(400, "Choose live or one dataset; models are trained per data source")
    return scope


@api.get("/ml/status")
def ml_status(scope: str = "live"):
    return ml.status(_conn(), _model_scope(scope))


@api.post("/ml/retrain")
def ml_retrain(scope: str = "live", _: dict = Depends(auth.require_admin)):
    with db.tx() as conn:
        return ml.train_and_activate(conn, _model_scope(scope))


def _parse_split(split: Optional[str]) -> Optional[float]:
    if not split:
        return None
    try:
        dt = datetime.fromisoformat(split.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "split must be a date like 2026-11-01 or 2026-11-12T13:30:00Z")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@api.get("/evaluation")
def run_evaluation(budget: int = Query(20, ge=1, le=500), split: Optional[str] = None,
                   include_demo: bool = False, scope: str = "live"):
    split_ts = None
    if split:
        try:
            dt = datetime.fromisoformat(split.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            split_ts = dt.timestamp()
        except ValueError:
            raise HTTPException(400, "split must be a date like 2026-11-01 or 2026-11-12T13:30:00Z")
    return evaluation.run(_conn(), budget=budget, split_ts=split_ts, include_demo=include_demo,
                          scope=_model_scope(scope))


@api.get("/meta")
def meta():
    return {
        "rules": RULE_CATALOG, "categories": CATEGORY_LABELS,
        "source": settings.source, "log_group": settings.log_group if settings.source == "cloudwatch" else None,
        "demo_cidrs": [str(n) for n in settings.demo_cidrs],
        "ml_include_demo": settings.ml_include_demo,
    }


# ------------------------------------------------------------------ provenance
@api.get("/provenance")
def provenance(scope: str = "live"):
    conn = _conn()
    if scope.startswith("ds:"):
        w, wa = _scope(scope)
        d = conn.execute("SELECT * FROM datasets WHERE id=?", wa).fetchone()
        if not d:
            raise HTTPException(404, "Dataset not found")
        return {"kind": "dataset", "source": f"Imported dataset · {d['name']}", "traffic": "Historical (imported)",
                "detail": f"{d['filename']} · {d['sessions']} sessions", "first_ts": d["first_ts"], "last_ts": d["last_ts"]}
    worker = db.get_checkpoint("worker_status") or {}
    src = worker.get("source") or settings.source
    source = "AWS sensor · CloudWatch Logs" if src == "cloudwatch" else "Local lab sensor · file"
    r = conn.execute("SELECT SUM(is_demo=1) demo, SUM(is_demo=0) real FROM sessions WHERE dataset_id IS NULL").fetchone()
    demo, real = r["demo"] or 0, r["real"] or 0
    traffic = ("No traffic yet" if demo + real == 0 else "Demo" if real == 0 else "Real" if demo == 0 else "Mixed")
    return {"kind": "live", "source": source, "traffic": traffic, "demo_sessions": demo, "real_sessions": real,
            "detail": f"{demo} demo / {real} real sessions"}


@api.get("/evaluation/plan")
def evaluation_plan(scope: str = "live", include_demo: bool = False, split: Optional[str] = None):
    return evaluation.plan(_conn(), scope=_model_scope(scope), include_demo=include_demo, split_ts=_parse_split(split))


# ------------------------------------------------------------------ access management (admin)
class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: Literal["analyst", "admin"] = "analyst"


class UserPatch(BaseModel):
    role: Optional[Literal["analyst", "admin"]] = None
    active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=256)


@api.get("/users")
def list_users(_: dict = Depends(auth.require_admin)):
    return {"items": [dict(r) for r in _conn().execute(
        "SELECT id, username, role, active, created_at, last_login, "
        "(SELECT COUNT(*) FROM auth_sessions s WHERE s.user_id = users.id AND s.expires_at > ?) sessions "
        "FROM users ORDER BY username", (time.time(),))]}


@api.post("/users")
def create_user(body: UserIn, _: dict = Depends(auth.require_admin)):
    with db.tx() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
            raise HTTPException(409, "That username is taken")
        cur = conn.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
                           (body.username, auth.hash_password(body.password), body.role, time.time()))
    return {"id": cur.lastrowid, "username": body.username, "role": body.role}


@api.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, me: dict = Depends(auth.require_admin)):
    if user_id == me["id"] and (body.active is False or body.role == "analyst"):
        raise HTTPException(400, "You can't disable or demote your own account")
    with db.tx() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise HTTPException(404, "User not found")
        if body.role:
            conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, user_id))
        if body.active is not None:
            conn.execute("UPDATE users SET active=? WHERE id=?", (1 if body.active else 0, user_id))
        if body.password:
            conn.execute("UPDATE users SET pw_hash=? WHERE id=?", (auth.hash_password(body.password), user_id))
        if body.role or body.active is False or body.password:
            conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))  # takes effect immediately
    return {"ok": True}


# ------------------------------------------------------------------ datasets
@api.get("/datasets")
def list_datasets():
    rows = _conn().execute("SELECT * FROM datasets ORDER BY created_at DESC").fetchall()
    out = []
    for r in rows:
        d = _dataset_out(r)
        if isinstance(d.get("report"), dict):
            d["report"].pop("sample_rows", None)
        out.append(d)
    return {"items": out}


@api.get("/datasets/{dataset_id}")
def get_dataset(dataset_id: int):
    row = _conn().execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Dataset not found")
    return _dataset_out(row)


@api.post("/datasets/upload")
async def upload_dataset(request: Request, filename: str = Query(..., min_length=1, max_length=200),
                         _: dict = Depends(auth.require_admin)):
    """Raw file body (no multipart). Streams it to disk, then validates it in a background process."""
    import shutil

    token, path = importer.new_upload(filename)
    folder = os.path.dirname(path)
    limit = settings.max_upload_mb * 1024 * 1024
    size = 0
    try:
        with open(path, "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"File is larger than the {settings.max_upload_mb} MB upload limit. "
                                             "Use the command-line importer for bigger files.")
                fh.write(chunk)
        if size == 0:
            raise HTTPException(400, "The uploaded file is empty.")
    except HTTPException:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    importer.start_validation(token)
    return {"token": token, "size_bytes": size}


@api.get("/datasets/uploads/{token}")
def upload_status(token: str, _: dict = Depends(auth.require_admin)):
    try:
        st = importer.read_status(token)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(404, str(exc))
    if st.get("state") == "ready":
        st["report"] = importer.read_report(token)
    st.pop("pid", None)
    return st


class RecheckIn(BaseModel):
    token: str = Field(min_length=8, max_length=64)
    mapping: dict[str, str]


@api.post("/datasets/recheck")
def recheck_dataset(body: RecheckIn, _: dict = Depends(auth.require_admin)):
    """CSV: validate again with an analyst-chosen column mapping (background)."""
    try:
        importer.upload_path(body.token)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(404, str(exc))
    importer.start_validation(body.token, {k: v for k, v in body.mapping.items() if k in importer.MAPPABLE and v})
    return {"token": body.token}


class ImportIn(BaseModel):
    token: str = Field(min_length=8, max_length=64)
    name: str = Field(min_length=1, max_length=120)


@api.post("/datasets/import")
def start_import(body: ImportIn, _: dict = Depends(auth.require_admin)):
    try:
        path = importer.upload_path(body.token)
        st = importer.read_status(body.token)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(404, str(exc))
    if st.get("state") != "ready":
        raise HTTPException(409, "This file is still being validated")
    report = importer.read_report(body.token) or {}
    if not report.get("accepted_rows"):
        raise HTTPException(400, "No row in this file passed validation, so there is nothing to import.")
    busy = importer.running_import()
    if busy:
        raise HTTPException(409, f"'{busy['name']}' is still importing. Start this one when it finishes.")
    ds_id = importer.create_dataset(body.name.strip(), os.path.basename(path), report)
    importer.start_import(ds_id, body.token)
    return {"id": ds_id, "status": "importing"}


@api.delete("/datasets/{dataset_id}")
def remove_dataset(dataset_id: int, _: dict = Depends(auth.require_admin)):
    row = _conn().execute("SELECT status FROM datasets WHERE id=?", (dataset_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Dataset not found")
    if row["status"] == "importing":
        raise HTTPException(409, "This dataset is still importing; wait for it to finish")
    importer.delete_dataset(dataset_id)
    return {"deleted": dataset_id}


app.include_router(api)
